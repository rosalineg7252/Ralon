//! Gemini CLI: `.gemini/settings.json`, `BeforeTool`.
//!
//! Two differences from the others, both real rather than cosmetic:
//!
//! - The event is `BeforeTool`, not `PreToolUse`.
//! - It refuses with `{"decision": "deny", "reason": ...}` on stdout and exit
//!   **0**, not with a non-zero exit. `hook check` prints that key alongside
//!   the others, so the one document works here too — but the exit code is not
//!   what makes it stick, which is worth knowing when reading the JSON.
//!
//! Its tools are snake_case (`write_file`, `replace`, `run_shell_command`) and
//! the matcher is a regex over that name.

use serde_json::{json, Value};

/// The agent's file-writing tools. `replace` is Gemini CLI's in-place edit.
const MATCHER: &str = "write_file|replace|edit";

pub const SETTINGS: &str = ".gemini/settings.json";

pub const EVENT: &str = "BeforeTool";

pub fn entry() -> Value {
    json!({
        "matcher": MATCHER,
        "hooks": [{
            "type": "command",
            "command": "ralon hook check"
        }]
    })
}

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
