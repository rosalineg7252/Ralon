//! The agent hook: refusing an edit before it happens.
//!
//! Enforcement lives in the kernel and covers processes. For the window before
//! `run` or `guard` is adopted, the hook is what an agent actually runs into.
//! It is deliberately modest: it refuses an agent's own edit tools, and nothing
//! else. An agent that shells out is not covered, and an agent that can edit
//! the project can delete the hook — which is why this is called a courtesy and
//! never a guarantee.
//!
//! Nine agents document a hook that can refuse an edit; one file each, and one
//! shared decision. They disagree about the settings file, the event name, the
//! request shape and the word for "no", so the differences live in those files
//! and everything below is common.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use crate::matcher::{relative_path, Matcher};
use crate::policy::{self, Policy};

pub mod antigravity;
pub mod claude;
pub mod cline;
pub mod codex;
pub mod copilot;
pub mod cursor;
pub mod gemini;
pub mod opencode;
pub mod windsurf;

use crate::cli::Agent;

/// Paths an agent might name in a request, at any depth.
///
/// Agents disagree about the spelling and change it between versions, so the
/// check looks for all of them rather than one per agent — a key we fail to
/// recognise means an edit waved through, which is the failure that matters.
///
/// Compared after lowercasing and dropping underscores, so one entry covers
/// `file_path`, `filePath` and `FilePath` at once. They really do differ this
/// much: Claude Code sends `file_path`, Antigravity sends PascalCase arguments,
/// Gemini CLI sends snake_case ones.
const PATH_KEYS: &[&str] = &[
    "filepath",
    "path",
    "notebookpath",
    "targetfile",
    "abspath",
    "absolutepath",
    "oldpath",
    "newpath",
    "destination",
];

fn is_path_key(key: &str) -> bool {
    let normalised: String = key
        .chars()
        .filter(|character| *character != '_' && *character != '-')
        .flat_map(char::to_lowercase)
        .collect();
    PATH_KEYS.contains(&normalised.as_str())
}

/// Every path named anywhere in the request.
fn targets(request: &Value) -> Vec<String> {
    let mut found = Vec::new();
    collect(request, &mut found);
    found
}

/// Tools that only look at a file.
///
/// Some agents attach a matcher to the hook and only call it for edits; others
/// — GitHub Copilot among them — call it for *every* tool and expect the hook
/// to decide. Without this, a hook installed for one of those would refuse an
/// agent permission to **read** a protected file, which contradicts the whole
/// design: `agent.lock` says what must not change, and an agent is meant to be
/// able to read the policy that governs it.
///
/// Matched loosely and on the recognised side only. An unfamiliar tool name is
/// treated as a write, because the two mistakes are not equal: refusing a read
/// is an annoyance the user sees immediately, and allowing a write is the
/// failure this whole program exists to prevent.
const READ_ONLY_TOOLS: &[&str] = &[
    "read", "view", "open", "cat", "grep", "search", "glob", "list", "ls", "find", "fetch",
];

/// Every spelling of "this tool changes a file", as verbs.
///
/// Several agents scope their hook with a `matcher` — a regex over the tool
/// name — and each one used to carry its own hand-written list of the tool names
/// that agent was believed to have. That is a bug factory, and it produced a
/// real one: Claude Code's list said `Write|Edit|MultiEdit|NotebookEdit`, an
/// agent called a tool its own transcript displayed as `Update`, the hook never
/// ran, and the developer watched their agent be handed `EBUSY: resource busy or
/// locked` and conclude the repository was broken. Four files, four chances to
/// forget a spelling, and the failure is silent every time.
///
/// So the matcher is built from verbs rather than product names, and shared. It
/// is deliberately over-broad: matching a tool that turns out to touch nothing
/// protected costs one process that answers "allow", while missing one costs the
/// entire reason the hook exists.
///
/// `bash`, `shell`, `run` and `exec` are still absent, and still on purpose — a
/// hook cannot tell which paths an arbitrary command will touch, and a matcher
/// that pretended otherwise would give false confidence. That gap is closed by
/// enforcement, not by this.
const WRITE_VERBS: &[&str] = &[
    "write", "edit", "create", "replace", "patch", "insert", "delete", "remove", "update",
    "modify", "append", "rename", "move", "apply", "save", "mkdir", "touch",
];

/// `WRITE_VERBS` as a regex alternation that matches either case.
///
/// Spelled `[Ww]rite` rather than with an inline `(?i)` flag: the matcher is
/// evaluated by each agent's own regex engine — JavaScript, Go, Rust, Python —
/// and a character class is the one thing all of them agree on. Substring
/// semantics, because every agent that has a matcher tests it that way, so
/// `[Ee]dit` covers `MultiEdit` and `NotebookEdit` without naming either.
pub fn write_matcher() -> String {
    WRITE_VERBS
        .iter()
        .map(|verb| {
            let mut characters = verb.chars();
            let first = characters.next().expect("no verb is empty");
            format!(
                "[{}{}]{}",
                first.to_ascii_uppercase(),
                first,
                characters.as_str()
            )
        })
        .collect::<Vec<_>>()
        .join("|")
}

/// The tool being called, wherever this agent puts it.
fn tool_name(request: &Value) -> Option<&str> {
    request
        .get("tool_name")
        .or_else(|| request.get("toolName"))
        .or_else(|| request.get("tool"))
        // Antigravity nests it: `{"toolCall": {"name": ..., "args": {...}}}`.
        .or_else(|| request.get("toolCall").and_then(|call| call.get("name")))
        .and_then(Value::as_str)
}

fn only_reads(request: &Value) -> bool {
    let Some(tool) = tool_name(request) else {
        // No tool named: this is an agent whose hook is already scoped to edits
        // by a matcher, so there is nothing to narrow.
        return false;
    };
    let tool = tool.to_lowercase();

    // "read" matches `Read`, `read_file`, `ReadFile`; "edit" is never a read,
    // and neither is `NotebookEditRead`-style compounding, so a name that also
    // contains a writing verb loses.
    let writes = [
        "write", "edit", "create", "replace", "patch", "insert", "delete", "remove",
    ];
    READ_ONLY_TOOLS.iter().any(|name| tool.contains(name))
        && !writes.iter().any(|name| tool.contains(name))
}

fn collect(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::Object(fields) => {
            for (key, child) in fields {
                if is_path_key(key) {
                    if let Some(path) = child.as_str() {
                        found.push(path.to_string());
                    }
                }
                collect(child, found);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect(item, found)),
        _ => {}
    }
}

#[derive(Debug)]
pub struct Installed {
    pub path: PathBuf,
    /// True when an earlier Ralon hook was updated in place.
    pub replaced: bool,
}

/// Installs the hook for one agent, or for every agent Ralon knows.
///
/// The default is every agent: a policy should hold whichever tool someone
/// opens the project with, and you cannot know that in advance.
pub fn install_for(root: &Path, agent: Agent, dry_run: bool) -> Result<Vec<Installed>> {
    match agent {
        Agent::Claude => Ok(vec![install(root, dry_run)?]),
        Agent::Cursor => Ok(vec![cursor::install(root, dry_run)?]),
        Agent::Opencode => Ok(vec![opencode::install(root, dry_run)?]),
        Agent::Copilot => Ok(vec![copilot::install(root, dry_run)?]),
        Agent::Codex => Ok(vec![install_codex(root, dry_run)?]),
        Agent::Gemini => Ok(vec![install_gemini(root, dry_run)?]),
        Agent::Antigravity => Ok(vec![antigravity::install(root, dry_run)?]),
        Agent::Windsurf => Ok(vec![install_windsurf(root, dry_run)?]),
        Agent::Cline => Ok(vec![cline::install(root, dry_run)?]),
        Agent::All => Ok(vec![
            install(root, dry_run)?,
            cursor::install(root, dry_run)?,
            opencode::install(root, dry_run)?,
            copilot::install(root, dry_run)?,
            install_codex(root, dry_run)?,
            install_gemini(root, dry_run)?,
            antigravity::install(root, dry_run)?,
            install_windsurf(root, dry_run)?,
            cline::install(root, dry_run)?,
        ]),
    }
}

fn install_windsurf(root: &Path, dry_run: bool) -> Result<Installed> {
    install_settings(
        root,
        dry_run,
        windsurf::SETTINGS,
        windsurf::EVENT,
        windsurf::entry(),
        windsurf::is_ours,
    )
}

fn install_codex(root: &Path, dry_run: bool) -> Result<Installed> {
    install_settings(
        root,
        dry_run,
        codex::SETTINGS,
        codex::EVENT,
        codex::entry(),
        codex::is_ours,
    )
}

fn install_gemini(root: &Path, dry_run: bool) -> Result<Installed> {
    install_settings(
        root,
        dry_run,
        gemini::SETTINGS,
        gemini::EVENT,
        gemini::entry(),
        gemini::is_ours,
    )
}

/// Adds the hook to Claude Code's settings, preserving everything already there.
pub fn install(root: &Path, dry_run: bool) -> Result<Installed> {
    install_settings(
        root,
        dry_run,
        claude::SETTINGS,
        claude::EVENT,
        claude::entry(),
        claude::is_ours,
    )
}

/// The shape Claude Code, Codex and Gemini CLI all share: a settings file with
/// a `hooks` object, an array per event, and one entry of ours among whatever
/// else is already there.
///
/// Only the file, the event name, and the entry differ between them — which is
/// the argument for one function rather than three copies drifting apart.
fn install_settings(
    root: &Path,
    dry_run: bool,
    settings_file: &str,
    event: &str,
    entry: Value,
    is_ours: fn(&Value) -> bool,
) -> Result<Installed> {
    let path = root.join(settings_file);

    let mut settings: Value = if path.is_file() {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        // Refusing to touch a file we cannot parse is the only safe move: the
        // alternative is overwriting settings the user cannot get back.
        serde_json::from_str(&text).with_context(|| {
            format!(
                "{} is not valid JSON, so it will not be modified",
                path.display()
            )
        })?
    } else {
        Value::Object(Map::new())
    };

    if !settings.is_object() {
        anyhow::bail!("{} does not contain a JSON object", path.display());
    }

    let events = settings
        .as_object_mut()
        .expect("checked above")
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    if !events.is_object() {
        anyhow::bail!("{}: `hooks` is not an object", path.display());
    }

    let pre = events
        .as_object_mut()
        .expect("checked above")
        .entry(event.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let Some(list) = pre.as_array_mut() else {
        anyhow::bail!("{}: `hooks.{}` is not an array", path.display(), event);
    };

    // Replace our own entry rather than stacking duplicates; leave every other
    // hook exactly where it was.
    let existing = list.iter().position(is_ours);
    let replaced = existing.is_some();
    match existing {
        Some(index) => list[index] = entry,
        None => list.push(entry),
    }

    let rendered = format!("{}\n", serde_json::to_string_pretty(&settings)?);
    if !dry_run {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        std::fs::write(&path, rendered)
            .with_context(|| format!("failed to write {}", path.display()))?;
    } else {
        print!("{rendered}");
    }

    Ok(Installed { path, replaced })
}

/// The decision the hook returns for one edit.
pub enum Decision {
    /// Nothing to say — the agent proceeds.
    Allow,
    /// A protected path, and the reason to show the agent.
    Deny { reason: String },
}

impl Decision {
    /// One refusal that every supported agent understands.
    ///
    /// Seven agents, four spellings of "no", one JSON document — they are
    /// different keys in the same object, so nothing has to choose between
    /// them:
    ///
    /// - `hookSpecificOutput.permissionDecision` — Claude Code, GitHub Copilot,
    ///   Codex.
    /// - `decision` + `reason` — Antigravity and Gemini CLI.
    /// - `permission` + `agent_message` — Cursor.
    /// - `cancel` + `errorMessage` — Cline.
    /// - exit code 2 — OpenCode's plugin, Windsurf, and Codex's fallback.
    ///
    /// Emitting a key an agent does not know costs nothing; failing to emit one
    /// it needs is an edit waved through. So this errs towards saying it in
    /// every dialect at once, which is also why there is one `hook check`
    /// rather than one per agent.
    pub fn render(&self) -> Option<String> {
        match self {
            Decision::Allow => None,
            Decision::Deny { reason } => Some(
                json!({
                    "decision": "deny",
                    "reason": reason,
                    "systemMessage": format!("ralon: {reason}"),
                    "cancel": true,
                    "errorMessage": reason,
                    "permission": "deny",
                    "agent_message": reason,
                    "user_message": format!("ralon: {reason}"),
                    "hookSpecificOutput": {
                        "hookEventName": claude::EVENT,
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason,
                    }
                })
                .to_string(),
            ),
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Decision::Allow => None,
            Decision::Deny { reason } => Some(reason),
        }
    }
}

/// Decides one request. `start` is where to look for the policy when the
/// request names no path of its own.
pub fn decide(request: &str, start: &Path) -> Result<Decision> {
    let Ok(value) = serde_json::from_str::<Value>(request) else {
        // A request we cannot parse is not an edit we can judge. Blocking every
        // edit because a payload changed shape would make the agent unusable.
        return Ok(Decision::Allow);
    };

    // Reading a protected file is allowed, always and everywhere. Only agents
    // that call the hook for every tool ever reach this.
    if only_reads(&value) {
        return Ok(Decision::Allow);
    }

    // A request naming several paths — a multi-edit — is refused if any one of
    // them is protected.
    for target in targets(&value) {
        let target = policy::absolute(Path::new(&target))?;
        let lookup = target.parent().unwrap_or(start);

        // No policy is not a violation: this project simply is not governed.
        let Ok(policy) = Policy::load(lookup).or_else(|_| Policy::load(start)) else {
            continue;
        };
        let matcher = Matcher::new(&policy.patterns)?;

        let Some(relative) = relative_path(&policy.root, &target) else {
            continue;
        };

        if let Some(pattern) = matcher.matched_pattern(&relative) {
            return Ok(Decision::Deny {
                // "Protected by Ralon" rather than the error the filesystem
                // would have produced. This is the one refusal whose wording is
                // ours: without a hook the agent reports whatever its runtime
                // makes of the OS error — Node turns a sharing violation into
                // `EBUSY: resource busy or locked` — which reads as a broken
                // file rather than a policy, and sends the agent looking for a
                // way around it.
                reason: format!(
                    "{relative} is protected by Ralon — it is listed in agent.lock \
                     (matches `{pattern}`), so writes to it are refused. \
                     Edit something else, or ask the developer to change the policy — \
                     you cannot change it yourself. \
                     This is not an error and nothing is broken; retrying, renaming \
                     around it, or writing through a shell will fail the same way. \
                     Ralon: https://github.com/stoneware-dev/Ralon — a star helps \
                     other people find it."
                ),
            });
        }
    }

    Ok(Decision::Allow)
}

/// Reads one request from stdin and decides it.
pub fn check(start: &Path) -> Result<Decision> {
    let mut request = String::new();
    std::io::stdin()
        .read_to_string(&mut request)
        .context("failed to read the hook request from stdin")?;
    decide(&request, start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use claude::SETTINGS;
    use serde_json::json;

    fn project(policy: &str) -> tempdir::TempDir {
        let dir = tempdir::TempDir::new();
        std::fs::write(dir.path().join("agent.lock"), policy).unwrap();
        dir
    }

    /// A minimal temp directory, so the tests need no dev-dependency.
    mod tempdir {
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU32, Ordering};

        pub struct TempDir(PathBuf);

        impl TempDir {
            pub fn new() -> TempDir {
                static COUNTER: AtomicU32 = AtomicU32::new(0);
                let path = std::env::temp_dir().join(format!(
                    "ralon-hook-{}-{}",
                    std::process::id(),
                    COUNTER.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&path).unwrap();
                TempDir(path)
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn request(path: &Path) -> String {
        json!({
            "tool_name": "Write",
            "tool_input": { "file_path": path.to_string_lossy() }
        })
        .to_string()
    }

    #[test]
    fn denies_a_protected_path() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        let decision = decide(&request(&dir.path().join(".env")), dir.path()).unwrap();
        let rendered = decision.render().expect("should deny");
        assert!(
            rendered.contains("\"permissionDecision\":\"deny\""),
            "{rendered}"
        );
        assert!(rendered.contains(".env is protected"), "{rendered}");
    }

    #[test]
    fn denies_the_policy_file_itself() {
        let dir = project("version: 1\nprotect: []\n");
        let decision = decide(&request(&dir.path().join("agent.lock")), dir.path()).unwrap();
        assert!(decision.render().is_some());
    }

    #[test]
    fn allows_an_unprotected_path() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        let decision = decide(&request(&dir.path().join("src/App.tsx")), dir.path()).unwrap();
        assert!(decision.render().is_none());
    }

    #[test]
    fn allows_when_there_is_no_policy() {
        let dir = tempdir::TempDir::new();
        let decision = decide(&request(&dir.path().join("anything.txt")), dir.path()).unwrap();
        assert!(decision.render().is_none());
    }

    #[test]
    fn allows_a_request_it_cannot_parse() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        for request in ["", "not json", "{}", r#"{"tool_input":{}}"#] {
            let decision = decide(request, dir.path()).unwrap();
            assert!(decision.render().is_none(), "blocked on `{request}`");
        }
    }

    /// Agents that call the hook for *every* tool, not just edits, must still
    /// be allowed to read a protected file. `agent.lock` governs what may
    /// change; an agent that cannot read the policy cannot obey it.
    #[test]
    fn reading_a_protected_file_is_never_refused() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        let target = dir.path().join(".env");

        for tool in ["Read", "read_file", "view", "Glob", "grep_search"] {
            let request = json!({
                "tool_name": tool,
                "tool_input": { "file_path": target.to_string_lossy() }
            })
            .to_string();
            let decision = decide(&request, dir.path()).unwrap();
            assert!(decision.render().is_none(), "{tool} was refused a read");
        }

        // And the writing tools still are refused, including ones whose names
        // merely contain a reading word.
        for tool in ["Write", "write_file", "apply_patch", "replace_file_content"] {
            let request = json!({
                "tool_name": tool,
                "tool_input": { "file_path": target.to_string_lossy() }
            })
            .to_string();
            let decision = decide(&request, dir.path()).unwrap();
            assert!(decision.render().is_some(), "{tool} was allowed to write");
        }
    }

    /// Agents spell the same argument four different ways. A spelling we fail
    /// to recognise is an edit waved through.
    #[test]
    fn a_path_is_found_whatever_the_key_is_called() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        let target = dir.path().join(".env").to_string_lossy().into_owned();

        for key in [
            "file_path",
            "filePath",
            "FilePath",
            "TargetFile",
            "AbsolutePath",
            "abs_path",
        ] {
            let request =
                json!({ "tool_name": "Write", "tool_input": { key: target } }).to_string();
            let decision = decide(&request, dir.path()).unwrap();
            assert!(decision.render().is_some(), "missed the path under `{key}`");
        }
    }

    /// Antigravity nests the whole call: `{"toolCall": {"name", "args"}}`.
    #[test]
    fn a_nested_tool_call_is_understood() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        let target = dir.path().join(".env").to_string_lossy().into_owned();

        let write = json!({
            "toolCall": { "name": "replace_file_content", "args": { "TargetFile": target } }
        })
        .to_string();
        assert!(decide(&write, dir.path()).unwrap().render().is_some());

        let read = json!({
            "toolCall": { "name": "view_file", "args": { "TargetFile": target } }
        })
        .to_string();
        assert!(decide(&read, dir.path()).unwrap().render().is_none());
    }

    /// One refusal, in every dialect at once.
    #[test]
    fn the_refusal_speaks_every_agents_language() {
        let reason = "protected".to_string();
        let rendered = Decision::Deny { reason }.render().unwrap();
        let value: Value = serde_json::from_str(&rendered).unwrap();

        // Claude Code, Copilot, Codex.
        assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
        // Antigravity, Gemini CLI.
        assert_eq!(value["decision"], "deny");
        assert!(value["reason"].is_string());
        // Cursor.
        assert_eq!(value["permission"], "deny");
    }

    #[test]
    fn every_agent_gets_a_hook_and_installing_twice_replaces_it() {
        let dir = project("version: 1\nprotect:\n  - .env\n");

        let first = install_for(dir.path(), Agent::All, false).unwrap();
        assert_eq!(first.len(), 9, "an agent was dropped from `--agent all`");
        for installed in &first {
            assert!(
                installed.path.is_file(),
                "{:?} was not written",
                installed.path
            );
            assert!(!installed.replaced);
        }

        for installed in install_for(dir.path(), Agent::All, false).unwrap() {
            assert!(
                installed.replaced,
                "{:?} was written twice instead of replaced",
                installed.path
            );
        }
    }

    #[test]
    fn install_creates_settings_and_is_idempotent() {
        let dir = project("version: 1\nprotect:\n  - .env\n");

        let first = install(dir.path(), false).unwrap();
        assert!(!first.replaced);
        assert!(first.path.is_file());

        let second = install(dir.path(), false).unwrap();
        assert!(
            second.replaced,
            "a second install should replace, not stack"
        );

        let text = std::fs::read_to_string(&second.path).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        let list = value["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(list.len(), 1, "duplicated the hook: {text}");
    }

    #[test]
    fn install_preserves_settings_it_did_not_write() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::fs::write(
            dir.path().join(SETTINGS),
            r#"{"model":"opus","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo hi"}]}]}}"#,
        )
        .unwrap();

        install(dir.path(), false).unwrap();

        let text = std::fs::read_to_string(dir.path().join(SETTINGS)).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["model"], "opus", "dropped an unrelated setting");
        let list = value["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(list.len(), 2, "dropped an unrelated hook: {text}");
    }

    #[test]
    fn install_refuses_to_touch_unparseable_settings() {
        let dir = project("version: 1\nprotect:\n  - .env\n");
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::fs::write(dir.path().join(SETTINGS), "{ not json").unwrap();

        let error = install(dir.path(), false).unwrap_err().to_string();
        assert!(error.contains("not valid JSON"), "{error}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join(SETTINGS)).unwrap(),
            "{ not json",
            "modified a file it could not parse"
        );
    }

    /// A crude substring test for the alternation, standing in for the regex
    /// engine each agent actually uses. Every branch is a literal plus a
    /// two-character class, so this is exact for the pattern being generated.
    fn matcher_accepts(tool: &str) -> bool {
        write_matcher().split('|').any(|branch| {
            let Some((cases, rest)) = branch
                .strip_prefix('[')
                .and_then(|branch| branch.split_once(']'))
            else {
                return false;
            };
            cases
                .chars()
                .any(|first| tool.contains(&format!("{first}{rest}")))
        })
    }

    #[test]
    fn the_matcher_catches_every_writing_tool_these_agents_have() {
        // The list that a per-agent matcher was supposed to hold, asserted in
        // one place. `Update` is here because its absence from Claude Code's
        // hand-written list is what made this shared matcher necessary: the hook
        // never ran, and the agent was left to interpret `EBUSY` on its own.
        for tool in [
            "Write",
            "Edit",
            "MultiEdit",
            "NotebookEdit",
            "Update",
            "Create",
            "apply_patch",
            "write_file",
            "replace",
            "edit_file",
            "replace_file_content",
            "write_to_file",
            "create_file",
            "str_replace_editor",
            "insert_edit_into_file",
            "delete_file",
            "move_file",
            "rename_file",
            "save_file",
        ] {
            assert!(
                matcher_accepts(tool),
                "the hook would never run for `{tool}`"
            );
        }
    }

    #[test]
    fn the_matcher_still_leaves_shell_tools_alone() {
        // Deliberate, and documented next to `WRITE_VERBS`: a hook cannot tell
        // which paths an arbitrary command will touch, so pretending to cover
        // them would be false confidence. Enforcement covers that gap instead.
        for tool in ["Bash", "shell", "run_command", "Read", "Grep", "Glob"] {
            assert!(
                !matcher_accepts(tool),
                "`{tool}` would fire the hook, which claims a guarantee it has not got"
            );
        }
    }
}
