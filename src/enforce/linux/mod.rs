//! Linux enforcement.
//!
//! Both backends restrict the *current* process and then `exec` the target
//! command: Landlock domains and namespaces are inherited across `exec` and by
//! every descendant, and neither can be dropped once entered. There is no
//! supervisor process to bypass or kill.

mod landlock;
mod mount;
mod sys;

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};

use anyhow::{anyhow, Result};

use super::{Availability, Backend, Plan};

pub fn availability() -> Vec<(Backend, Availability)> {
    vec![
        (Backend::Mount, mount::availability()),
        (Backend::Landlock, landlock::availability()),
    ]
}

pub fn enforce_and_exec(plan: &Plan, command: &[OsString]) -> Result<ExitCode> {
    match plan.backend {
        Backend::Mount => mount::apply(&plan.pinned, &plan.protected)?,
        Backend::Landlock => match &plan.carve {
            Some(carve) => landlock::apply(carve)?,
            None => return Err(anyhow!("internal error: landlock plan was not built")),
        },
        other => return Err(anyhow!("internal error: {other} cannot enforce on Linux")),
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
