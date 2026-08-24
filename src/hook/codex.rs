//! OpenAI Codex: `.codex/hooks.json`, `PreToolUse`.
//!
//! The same shape as Claude Code's, down to the field names — a `matcher`, a
//! nested `hooks` array, `type` and `command` — and the same two ways to
//! refuse: `permissionDecision: "deny"`, or exit code 2 with the reason on
//! stderr. `hook check` does both.
//!
//! The matcher is where Codex differs. Its edit tool is `apply_patch`, which
//! also matches `Edit` and `Write`, and the matcher is a regex over the tool
//! name — MCP tools included. `Bash` is left out for the reason it is left out
//! everywhere else: a hook cannot tell which paths a shell command will touch.

use serde_json::{json, Value};

/// The agent's file-writing tools.
const MATCHER: &str = "apply_patch|Edit|Write";

/// Codex reads `hooks.json` beside the repo's config, or an inline `[hooks]`
/// table in `config.toml`. The JSON file is the one Ralon writes: it can be
/// created and replaced whole without touching settings someone else owns.
pub const SETTINGS: &str = ".codex/hooks.json";

pub const EVENT: &str = "PreToolUse";

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
