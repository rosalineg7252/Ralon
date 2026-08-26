//! Platforms where a policy cannot be held open on its own.
//!
//! Linux, in practice. Not an omission — the shape of the mechanism.
//!
//! Enforcement here is a restriction applied to a process *before* it runs: a
//! Landlock domain and a locked mount namespace are both inherited, never
//! imposed, so there is no way for a process to reach out and restrict another
//! one it did not start. The interfaces that could — `chattr +i`, fanotify
//! permission events, an LSM of one's own — all want privileges a developer tool
//! has no business holding, and asking for root to protect a file from an agent
//! gives the agent a root process to talk to.
//!
//! macOS used to be routed here too, on the grounds that `chflags uchg` is a
//! narrowing rather than a guard and should not be described as protection. It
//! is now implemented, in `enforce/macos/immutable.rs`, described as the
//! narrowing it is — because a supervisor needs *something* that can be imposed,
//! and on macOS that is the whole list. Linux has no equivalent: the immutable
//! bit exists but setting it needs `CAP_LINUX_IMMUTABLE`, which is root.
//!
//! So here `run` is not an inconvenience on the way to something better; it *is*
//! the something better. A guard would be a background process that could be
//! killed. `run` becomes the command, and cannot. `ralon install` says this in
//! as many words rather than registering a daemon with nothing to do.

use std::path::{Path, PathBuf};

use anyhow::Result;

use super::Plan;

pub const AVAILABLE: bool = false;

/// Never used — nothing here can start a guard — but it keeps the callers one
/// body of code rather than one per platform.
pub const BACKEND: super::Backend = super::Backend::Auto;

pub struct Session {
    /// Never populated — `start` never returns one. It exists so the caller is
    /// one body of code rather than two.
    pub warnings: Vec<String>,
}

impl Session {
    pub fn files(&self) -> usize {
        0
    }

    pub fn directories(&self) -> usize {
        0
    }

    pub fn refused_directories(&self) -> usize {
        0
    }

    pub fn park(self) -> Result<()> {
        unreachable!("no session can be started on {}", std::env::consts::OS)
    }
}

pub fn start(_root: &Path, _plan: &Plan) -> Result<Session> {
    anyhow::bail!(
        "a guard cannot protect a process it did not start on {}. `ralon run -- <agent>` \
         restricts the agent and every process it spawns, which is stronger — it is \
         inherited rather than held, so there is nothing to kill.",
        std::env::consts::OS
    )
}

pub fn stop(_root: &Path) -> Result<bool> {
    Ok(false)
}

pub fn running(_root: &Path) -> bool {
    false
}

pub fn detach(root: &Path) -> Result<()> {
    start(root, &Plan::build(super::Backend::Auto, root, Vec::new())).map(|_| ())
}

pub fn silence_standard_handles() {}

pub fn leftovers(_protected: &[PathBuf]) -> Vec<PathBuf> {
    Vec::new()
}

pub fn clear_leftovers(_protected: &[PathBuf]) -> Vec<PathBuf> {
    Vec::new()
}
