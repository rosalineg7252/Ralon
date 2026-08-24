//! macOS enforcement — not implemented.
//!
//! This is the most tractable of the unimplemented platforms, because the
//! Seatbelt sandbox understands *deny* rules. Landlock does not, which is why
//! the Linux backend has to carve out every sibling of a protected path; a
//! Seatbelt profile can say the thing directly:
//!
//! ```text
//! (version 1)
//! (allow default)
//! (deny file-write* (literal "/Users/dev/proj/.env")
//!                   (subpath "/Users/dev/proj/config"))
//! ```
//!
//! `sandbox_init` applies such a profile to the calling process, and it is
//! inherited across `exec` — the same shape as `run` uses everywhere else, so
//! `Plan` needs no new concepts, only a profile writer.
//!
//! What has to be settled before this ships:
//!
//! - `sandbox_init` has been deprecated since 10.8 and is not a supported API.
//!   It still works and is what several shipping sandboxes use, but Ralon
//!   claims a *guarantee*, so relying on it needs a decision, not a shrug.
//! - Deny rules take the path as written. A protected file reachable by a
//!   second path — a hard link, a firmlink, `/tmp` vs `/private/tmp` — is not
//!   covered, exactly as on Linux. `audit` already reports both.
//! - `run` must keep refusing rather than half-applying: a profile the kernel
//!   rejects has to be an error, never a warning.

use std::ffi::OsString;
use std::process::ExitCode;

use anyhow::Result;

use super::{Availability, Backend, Plan};

pub fn availability() -> Vec<(Backend, Availability)> {
    let reason = "no backend is implemented for macOS yet; the Seatbelt sandbox could \
                  enforce this directly (see src/enforce/macos)"
        .to_string();
    vec![
        (
            Backend::Mount,
            Availability::Unavailable {
                reason: reason.clone(),
            },
        ),
        (Backend::Landlock, Availability::Unavailable { reason }),
    ]
}

pub fn enforce_and_exec(_plan: &Plan, _command: &[OsString]) -> Result<ExitCode> {
    Err(anyhow::anyhow!(
        "there is no enforcement backend for macOS yet, so nothing would be protected. \
         `ralon hook install` refuses an agent's own edit tools; `ralon check` works here \
         for hooks and CI."
    ))
}
