//! Every platform without a backend of its own.
//!
//! Reached on the BSDs, illumos, and anything else Rust compiles for. Ralon
//! builds and its policy commands work; only `run` is unavailable — which it
//! says, rather than starting the agent unprotected.

use std::ffi::OsString;
use std::process::ExitCode;

use anyhow::Result;

use super::{Availability, Backend, Plan};

pub fn availability() -> Vec<(Backend, Availability)> {
    let reason = format!("no enforcement backend exists for {}", std::env::consts::OS);
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
        "there is no enforcement backend for {}, so nothing would be protected",
        std::env::consts::OS
    ))
}
