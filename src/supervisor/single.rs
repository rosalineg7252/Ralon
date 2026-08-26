//! One supervisor per user, enforced by the kernel rather than by a pid file.
//!
//! Two supervisors would each try to start enforcement for the same workspaces
//! and write the same registry, and the second one's view would overwrite the
//! first's. A lock *file* would be the obvious fix and the wrong one: a pid
//! written to disk outlives the process that wrote it, so a supervisor killed by
//! a reboot leaves a claim nothing will ever release, and the next one has to
//! decide whether a recorded pid is alive — a question with no portable answer
//! and a wrong one every time a pid is reused.
//!
//! An open handle has none of that. It is held by a process, released by the
//! kernel when that process ends however it ended, and asking "is it held" is
//! the same operation as taking it. The same reasoning as `enforce/windows`:
//! state on disk needs undoing, state in the kernel does not.

use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result};

use super::registry;

const LOCK_FILE: &str = "supervisor.lock";

/// Held for as long as this supervisor runs.
pub struct Claim {
    #[allow(dead_code)]
    file: File,
}

/// Takes the claim, or fails because somebody else has it.
pub fn claim() -> Result<Claim> {
    let home = registry::home()?;
    std::fs::create_dir_all(&home)
        .with_context(|| format!("failed to create {}", home.display()))?;
    take(&home.join(LOCK_FILE))
}

/// Whether a supervisor is running right now.
///
/// Answered by trying to take the claim and giving it straight back. There is a
/// window between the two where this process holds it, so this must not be
/// called by anything that is about to start a supervisor — [`claim`] is the
/// one that both asks and keeps the answer.
pub fn running() -> bool {
    let Ok(home) = registry::home() else {
        return false;
    };
    let path = home.join(LOCK_FILE);
    if !path.exists() {
        return false;
    }
    take(&path).is_err()
}

#[cfg(windows)]
fn take(path: &Path) -> Result<Claim> {
    use std::os::windows::fs::OpenOptionsExt;

    // Share nothing: the second opener is refused by the same mechanism the
    // rest of the Windows backend runs on.
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .share_mode(0)
        .open(path)
        .with_context(|| format!("could not claim {}", path.display()))?;
    Ok(Claim { file })
}

#[cfg(unix)]
fn take(path: &Path) -> Result<Claim> {
    use std::os::unix::io::AsRawFd;

    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("could not open {}", path.display()))?;

    // Safety: a valid fd owned by `file`, which outlives the call. `LOCK_NB`
    // makes this ask rather than wait.
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if locked != 0 {
        anyhow::bail!("{} is held by another supervisor", path.display());
    }
    Ok(Claim { file })
}
