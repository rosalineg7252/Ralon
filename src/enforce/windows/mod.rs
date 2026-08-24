//! Windows enforcement.
//!
//! One backend, and it is not the one you would reach for first.
//!
//! **Not ACLs.** A deny entry looks right until you notice the agent runs as
//! the same user as Ralon: any permission Ralon can set, the agent can unset,
//! because the two processes are indistinguishable to the security descriptor.
//! Restricting the owner's implicit rights closes that — and locks Ralon out of
//! its own cleanup at the same time.
//!
//! **Share-mode handles instead.** Windows arbitrates two opens of the same
//! file by the share mode the first one asked for. Ralon holds every protected
//! file open allowing readers and refusing writers, so every attempt to write,
//! delete, or rename it fails with a sharing violation — for every process on
//! the machine, whichever agent it belongs to, whether or not that agent has
//! ever heard of a hook. Nothing is written to disk, so nothing needs undoing:
//! when this process ends the locks end with it.
//!
//! Two things it is not:
//!
//! - It is **not inherited**, the way a Landlock domain is: the protection
//!   lives in this process, so this backend supervises the command rather than
//!   `exec`ing it. An agent could therefore kill its supervisor and outlive the
//!   locks — so the command is put in a job object that dies with Ralon, and
//!   killing Ralon kills the command with it. Verified: with the supervisor
//!   terminated mid-run, the command never reached its write.
//! - A protected **directory** keeps every existing file inside it locked and
//!   cannot itself be renamed or removed, but a *new* file created inside it is
//!   not covered — verified, and the one gap the Linux backends do not have.

mod job;
mod locks;

use std::ffi::OsString;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result};

use super::{Availability, Backend, Plan};

pub fn availability() -> Vec<(Backend, Availability)> {
    let linux_only = |feature: &str| Availability::Unavailable {
        reason: format!("{feature} is a Linux kernel feature with no Windows equivalent"),
    };

    vec![
        (Backend::Mount, linux_only("mount namespaces")),
        (Backend::Landlock, linux_only("Landlock")),
        (
            Backend::Locks,
            Availability::Available {
                detail: "exclusive share-mode handles, held for the life of the command"
                    .to_string(),
            },
        ),
    ]
}

pub fn enforce_and_exec(plan: &Plan, command: &[OsString]) -> Result<ExitCode> {
    let Some((program, arguments)) = command.split_first() else {
        anyhow::bail!("no command given");
    };

    // Taken before the command starts: if a path cannot be locked, nothing runs.
    let held = locks::acquire(&plan.pinned, &plan.protected)?;

    let mut child = Command::new(program)
        .args(arguments)
        .spawn()
        .with_context(|| format!("failed to run `{}`", program.to_string_lossy()))?;

    // The agent runs as this user and can terminate its own supervisor. Tying
    // it to a job that dies with Ralon means it cannot outlive the locks.
    let leash = job::tie_to_this_process(&child);
    if leash.is_none() {
        eprintln!(
            "ralon: warning: this command could not be tied to Ralon's lifetime, so \
             killing Ralon would release the locks while the command keeps running"
        );
    }

    let status = child
        .wait()
        .context("failed to wait for the command to finish")?;

    // Explicit, so the handles outlive the child rather than being dropped
    // early by an optimiser or a future edit that moves things around.
    drop(leash);
    drop(held);

    // The command's own status, as on every other platform.
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}
