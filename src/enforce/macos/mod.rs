//! macOS enforcement.
//!
//! One backend, and it is the closest of the three platforms to the policy as
//! written. Seatbelt understands *deny*, so `agent.lock` becomes a profile that
//! says the same thing:
//!
//! ```text
//! (version 1)
//! (allow default)
//! (deny file-write* (literal "/Users/dev/proj/.env")
//!                   (subpath "/Users/dev/proj/config"))
//! ```
//!
//! What that buys over the other two:
//!
//! - Nothing outside the named paths behaves differently, like the mount
//!   backend and unlike Landlock, which has to grant every sibling and leaves
//!   the ancestor directories create-restricted.
//! - A protected *directory* covers entries created inside it later, unlike the
//!   Windows locks, which can only refuse an open of something that exists and
//!   need an ACL to reach the rest.
//! - It is inherited across `exec` and cannot be dropped, so `run` becomes the
//!   command and there is no supervisor to kill — the Linux property, which
//!   Windows cannot have.
//!
//! What it does not do is guard: a profile restricts the process it was applied
//! to and its descendants, so like Linux it cannot cover an agent it did not
//! start.
//!
//! That is what the second entry here is for. `immutable` — `chflags uchg` — is
//! the only mechanism on macOS a background process can impose on an agent
//! nobody started, so it is what `ralon guard` and the supervisor use. It is
//! strictly weaker than Seatbelt and `immutable.rs` says exactly how; it is not
//! offered to `run`, which has something better, and `Backend::Auto` never
//! selects it.
//!
//! The known costs are in `security.md`: `sandbox_init` is deprecated, and rules
//! name paths, so a hard link or a second path to the same file is outside them
//! — which `audit.rs` already reports.

pub mod guard;
pub mod immutable;
mod seatbelt;

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};

use anyhow::{anyhow, Result};

use super::{Availability, Backend, Plan};

pub fn availability() -> Vec<(Backend, Availability)> {
    let linux_only = |feature: &str| Availability::Unavailable {
        reason: format!("{feature} is a Linux kernel feature with no macOS equivalent"),
    };

    let seatbelt = if seatbelt::available() {
        Availability::Available {
            detail: "Seatbelt, applied to this process and inherited by everything it starts"
                .to_string(),
        }
    } else {
        Availability::Unavailable {
            reason: "this build has no sandbox_init to call".to_string(),
        }
    };

    vec![
        (Backend::Mount, linux_only("mount namespaces")),
        (Backend::Landlock, linux_only("Landlock")),
        (Backend::Seatbelt, seatbelt),
        (
            Backend::Immutable,
            Availability::Available {
                detail: "chflags uchg, refused to every process until it is cleared — \
                         a narrowing an agent can undo with `chflags nouchg`, not a sandbox"
                    .to_string(),
            },
        ),
    ]
}

pub fn enforce_and_exec(plan: &Plan, command: &[OsString]) -> Result<ExitCode> {
    match plan.backend {
        Backend::Seatbelt => match &plan.profile {
            Some(profile) => seatbelt::apply(profile)?,
            None => {
                return Err(anyhow!(
                    "internal error: the seatbelt profile was not built"
                ))
            }
        },
        other => return Err(anyhow!("internal error: {other} cannot enforce on macOS")),
    }
    // Never returns on success: this process becomes the command.
    Err(exec(command))
}

/// Replaces this process with `command`.
fn exec(command: &[OsString]) -> anyhow::Error {
    let Some((program, arguments)) = command.split_first() else {
        return anyhow!("no command given");
    };
    let error = Command::new(program).args(arguments).exec();
    anyhow::Error::new(error).context(format!("failed to run `{}`", program.to_string_lossy()))
}
