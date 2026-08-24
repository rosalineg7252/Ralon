//! The agent hook: refusing an edit before it happens.
//!
//! Enforcement lives in the kernel and only exists on Linux. Everywhere else —
//! and for the window before `run` is adopted — the hook is what an agent
//! actually runs into. It is deliberately modest: it can refuse an agent's own
//! edit tools, and nothing else. An agent that shells out is not covered, which
//! is why this is called a courtesy and not a guarantee.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use crate::matcher::{relative_path, Matcher};
use crate::policy::{self, Policy};

pub mod claude;
pub mod cursor;
pub mod opencode;

use crate::cli::Agent;

/// Paths an agent might name in a request, at any depth. Agents disagree about
/// the spelling and change it between versions, so the check looks for all of
/// them rather than one per agent — a key we fail to recognise means an edit
/// waved through, which is the failure that matters.
const PATH_KEYS: &[&str] = &[
    "file_path",
    "filePath",
    "path",
    "notebook_path",
    "target_file",
    "abs_path",
];

/// Every path named anywhere in the request.
fn targets(request: &Value) -> Vec<String> {
    let mut found = Vec::new();
    collect(request, &mut found);
    found
}

fn collect(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::Object(fields) => {
            for (key, child) in fields {
                if PATH_KEYS.contains(&key.as_str()) {
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
        Agent::All => Ok(vec![
            install(root, dry_run)?,
            cursor::install(root, dry_run)?,
            opencode::install(root, dry_run)?,
        ]),
    }
}

/// Adds the hook to Claude Code's settings, preserving everything already there.
pub fn install(root: &Path, dry_run: bool) -> Result<Installed> {
    let path = root.join(claude::SETTINGS);

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
        .entry(claude::EVENT)
        .or_insert_with(|| Value::Array(Vec::new()));
    let Some(list) = pre.as_array_mut() else {
        anyhow::bail!(
            "{}: `hooks.{}` is not an array",
            path.display(),
            claude::EVENT
        );
    };

    // Replace our own entry rather than stacking duplicates; leave every other
    // hook exactly where it was.
    let existing = list.iter().position(claude::is_ours);
    let replaced = existing.is_some();
    match existing {
        Some(index) => list[index] = claude::entry(),
        None => list.push(claude::entry()),
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
    /// Claude Code reads `hookSpecificOutput.permissionDecision`; Cursor reads
    /// `permission` and `agent_message`. They are different keys in the same
    /// object, so one document satisfies both, and OpenCode's plugin only looks
    /// at the exit code. That is why there is one `hook check` rather than one
    /// per agent.
    pub fn render(&self) -> Option<String> {
        match self {
            Decision::Allow => None,
            Decision::Deny { reason } => Some(
                json!({
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
                reason: format!(
                    "{relative} is protected by agent.lock (matches `{pattern}`). \
                     Edit something else, or ask the developer to change the policy — \
                     you cannot change it yourself."
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
}
