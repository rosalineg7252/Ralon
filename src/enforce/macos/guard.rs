//! Holding a policy open on macOS, with no command to supervise.
//!
//! Unlike the Windows guard, there is no process holding anything. The
//! protection is a flag on each inode, so it survives this command exiting, a
//! logout, and a reboot — and equally, it stays behind if Ralon is killed before
//! it can clean up. That fails *closed*, which is the safe direction and the
//! same bargain the Windows deny ACE makes: `status` reports the leftover and
//! `ralon guard --stop` clears it.
//!
//! Read `immutable.rs` before relying on this. It is a narrowing, not the
//! boundary `ralon run` gives, and the difference is not a detail.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;

use super::immutable;
use crate::enforce::{Backend, Plan};
use crate::matcher::Matcher;
use crate::policy::{Policy, POLICY_FILE};
use crate::scan;

/// Whether this platform can protect a process it did not start.
pub const AVAILABLE: bool = true;

/// What a guard here enforces with. Not `Seatbelt`: a profile is inherited by
/// the process it is applied to, and a guard by definition has no such process.
pub const BACKEND: Backend = Backend::Immutable;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_signal: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// A running guard: the paths that were flagged, and anything worth saying.
pub struct Session {
    applied: Vec<PathBuf>,
    directories: usize,
    pub warnings: Vec<String>,
}

impl Session {
    pub fn files(&self) -> usize {
        self.applied.len() - self.directories
    }

    pub fn directories(&self) -> usize {
        self.directories
    }

    /// Every protected directory refuses new entries, because that is what the
    /// flag on a directory means. There is no separate mechanism for it here the
    /// way there is on Windows.
    pub fn refused_directories(&self) -> usize {
        self.directories
    }

    /// Blocks until interrupted, then gives the paths back on the way out.
    pub fn park(self) -> Result<()> {
        // Safety: installing a handler that only sets an atomic flag, which is
        // the one thing a signal handler is allowed to do here.
        // Through `*const ()` rather than straight to `sighandler_t`, which is
        // an integer: casting a function item to one directly is a lint, and
        // deservedly so — the pointer cast is the part that has meaning.
        unsafe {
            libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
            libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        }

        while !INTERRUPTED.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        // `self` is dropped here, which clears the flags.
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        for path in &self.applied {
            let _ = immutable::clear(path);
        }
    }
}

/// Flags everything the plan protects.
pub fn start(_root: &Path, plan: &Plan) -> Result<Session> {
    let (applied, directories, warnings) = apply(&plan.protected);
    if applied.is_empty() && !plan.protected.is_empty() {
        anyhow::bail!(
            "nothing could be made immutable — {}",
            warnings
                .first()
                .map(String::as_str)
                .unwrap_or("no reason given")
        );
    }
    Ok(Session {
        applied,
        directories,
        warnings,
    })
}

/// The same thing, without a session to hold.
///
/// On Windows this spawns a background process because the locks live in one.
/// Here the state is on the disk, so there is nothing to detach: applying the
/// flags *is* the durable form, and it outlives every process including this one.
pub fn detach(root: &Path) -> Result<()> {
    let protected = protected_paths(root)?;
    let (applied, _, warnings) = apply(&protected);
    for warning in &warnings {
        eprintln!("ralon: warning: {warning}");
    }
    if applied.is_empty() && !protected.is_empty() {
        anyhow::bail!(
            "nothing could be made immutable — {}",
            warnings
                .first()
                .map(String::as_str)
                .unwrap_or("no reason given")
        );
    }
    Ok(())
}

/// Clears the flags this project's policy accounts for.
///
/// `Ok(false)` means nothing was flagged. The policy is read rather than
/// remembered, which works because reading an immutable file is still allowed —
/// and when the policy is gone entirely, [`clear_leftovers`] takes the paths
/// from the caller instead.
pub fn stop(root: &Path) -> Result<bool> {
    let Ok(protected) = protected_paths(root) else {
        return Ok(false);
    };
    Ok(!clear_leftovers(&protected).is_empty())
}

/// Whether this project is currently held.
///
/// Decided by `agent.lock` itself, which every policy protects whether or not it
/// says so — so it is flagged exactly when enforcement is in place, and asking
/// costs one `lstat` rather than a walk of the project.
pub fn running(root: &Path) -> bool {
    immutable::is_set(&root.join(POLICY_FILE))
}

/// A no-op here: nothing is detached, so nothing loses its console.
pub fn silence_standard_handles() {}

pub fn leftovers(protected: &[PathBuf]) -> Vec<PathBuf> {
    protected
        .iter()
        .flat_map(|path| immutable::targets(path))
        .filter(|path| immutable::is_set(path))
        .collect()
}

/// Takes the flags off, and reports what it actually changed.
///
/// Checked afterwards rather than trusted — the rule this codebase learned from
/// `SetEntriesInAcl`, which reported success and changed nothing.
pub fn clear_leftovers(protected: &[PathBuf]) -> Vec<PathBuf> {
    let mut cleared = Vec::new();
    for path in protected {
        // Shallowest first, so a directory is writable again before anything
        // tries to reach the entries inside it.
        let mut targets = immutable::targets(path);
        targets.reverse();
        for target in targets {
            if !immutable::is_set(&target) {
                continue;
            }
            let _ = immutable::clear(&target);
            if !immutable::is_set(&target) {
                cleared.push(target);
            }
        }
    }
    cleared
}

/// Applies the flag, returning what stuck, how many were directories, and every
/// path that would not take it.
///
/// A path that cannot be flagged is a warning rather than a failure, matching
/// the Windows ACL: the rest of the policy is still worth enforcing, and the one
/// thing that must never happen is a path silently not being protected.
fn apply(protected: &[PathBuf]) -> (Vec<PathBuf>, usize, Vec<String>) {
    let mut applied = Vec::new();
    let mut directories = 0;
    let mut warnings = Vec::new();

    for path in protected {
        for target in immutable::targets(path) {
            let is_dir = target.is_dir();
            match immutable::set(&target) {
                Ok(()) => {
                    applied.push(target);
                    if is_dir {
                        directories += 1;
                    }
                }
                Err(errno) => warnings.push(immutable::explain(&target, errno)),
            }
        }
    }

    (applied, directories, warnings)
}

/// The canonical paths this project's policy protects.
fn protected_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let policy = Policy::load(root)?;
    let matcher = Matcher::new(&policy.patterns)?;
    let found = scan::scan(&policy.root, &matcher)?;
    scan::canonical_targets(&found)
}
