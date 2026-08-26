//! Noticing that an `agent.lock` appeared, without asking the disk repeatedly.
//!
//! Each platform has a kernel mechanism for this and each one is used:
//! `ReadDirectoryChangesW` on Windows, FSEvents on macOS. Both watch a whole
//! subtree from one registration, which is what makes "watch everywhere the
//! developer keeps code" affordable at all — the alternative, a watch per
//! directory, is thousands of registrations for one code root.
//!
//! ## Why there is still a sweep behind it
//!
//! Not as a substitute. A watcher reports *changes*, which means it has nothing
//! to say about the state that already existed when it started — after a reboot
//! that is every workspace on the machine — and both mechanisms are allowed to
//! coalesce or drop notifications when a lot happens at once. The sweep is what
//! makes the supervisor's correctness independent of a notification arriving;
//! the watcher is what makes it immediate. Removing the watcher would leave a
//! tool that works and feels broken. Removing the sweep would leave one that
//! demos well and silently misses a repository.
//!
//! It is also what a failed watcher degrades to. `start` never fails: a platform
//! whose watcher will not start reports itself and hands back [`sweep::Blind`],
//! and the supervisor keeps working a minute at a time.

use std::path::PathBuf;
use std::time::Duration;

pub mod sweep;

#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod platform;

#[cfg(target_os = "windows")]
#[path = "windows.rs"]
mod platform;

/// A source of "something under here changed".
pub trait Watcher: Send {
    /// Blocks for at most `timeout`. An empty result means the timeout elapsed,
    /// which is the supervisor's cue to run a full sweep.
    fn changes(&mut self, timeout: Duration) -> Vec<PathBuf>;

    /// What is actually watching, in a form worth putting in a log — including
    /// when the answer is "nothing, and here is why".
    fn describe(&self) -> String;
}

/// The best watcher this platform can give for `roots`.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn start(roots: &[PathBuf]) -> Box<dyn Watcher> {
    if roots.is_empty() {
        return Box::new(sweep::Blind::new(
            "no scan roots are configured, so nothing is being watched".to_string(),
        ));
    }
    match platform::start(roots) {
        Ok(watcher) => Box::new(watcher),
        Err(error) => Box::new(sweep::Blind::new(format!(
            "falling back to a {}s sweep — the watcher would not start: {error:#}",
            super::SWEEP_INTERVAL.as_secs()
        ))),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn start(_roots: &[PathBuf]) -> Box<dyn Watcher> {
    // Not an omission. There is no supervisor on these platforms — `install`
    // refuses — so this exists to keep the module compiling everywhere, which is
    // what lets the state machine above it be tested everywhere.
    Box::new(sweep::Blind::new(format!(
        "no supervisor runs on {}",
        std::env::consts::OS
    )))
}
