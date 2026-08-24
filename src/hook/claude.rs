//! Claude Code: `.claude/settings.json`, `PreToolUse`.
//!
//! One file per agent. Adding Cursor or Codex means another file with these
//! three functions, not an edit to the logic that decides what is protected —
//! which is the whole point of the policy being agent-independent.

use serde_json::{json, Value};

/// The agent's file-writing tools.
///
/// `Bash` is deliberately absent: a hook cannot tell which paths an arbitrary
/// shell command will touch, and a matcher that pretends otherwise would give
/// false confidence — worse than an honest gap.
const MATCHER: &str = "Write|Edit|MultiEdit|NotebookEdit";

/// Where the agent keeps per-project settings, relative to the project root.
pub const SETTINGS: &str = ".claude/settings.json";

/// The event whose entries this hook belongs to.
pub const EVENT: &str = "PreToolUse";

/// The entry to install.
pub fn entry() -> Value {
    json!({
        "matcher": MATCHER,
        "hooks": [{
            "type": "command",
            "command": "ralon hook check",
            "statusMessage": "Checking agent.lock"
        }]
    })
}

/// Whether an existing entry is one of ours, so installing twice updates it
/// instead of stacking duplicates.
pub fn is_ours(candidate: &Value) -> bool {
    candidate
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|hooks| {
            hooks.iter().any(|hook| {
                hook.get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|command| command.contains("ralon hook check"))
            })
        })
}

// Reading the request and writing the refusal are shared: see `hook::targets`
// and `Decision::render`. Agents disagree about the key an edit's path lives
// under, and one unrecognised spelling is an edit waved through, so the check
// looks for every spelling rather than one per agent.
