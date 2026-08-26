//! Registering the supervisor with whatever starts things on this machine.
//!
//! One job: make `ralon daemon` come back after a reboot without anybody typing
//! it. Each platform has a per-user mechanism for exactly this and each is used
//! as intended — a Task Scheduler logon task on Windows, a launchd LaunchAgent
//! on macOS. Both are per-user by construction, which is why none of this asks
//! for administrator or root. A tool that protects you from an agent should not
//! be the reason there is a privileged process on the machine for an agent to
//! talk to.
//!
//! Linux has the mechanism (a systemd user unit) and nothing for it to run: see
//! `unsupported.rs`.

#[cfg(target_os = "windows")]
#[path = "windows.rs"]
mod platform;

#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod platform;

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
#[path = "unsupported.rs"]
mod platform;

use std::path::PathBuf;

use anyhow::Result;

/// Whether a supervisor can be registered here at all.
pub const SUPPORTED: bool = platform::SUPPORTED;

/// What happened, in terms a person can check by hand afterwards.
pub struct Registration {
    /// The mechanism, named so it can be looked up: "a Task Scheduler logon
    /// task", "a launchd LaunchAgent".
    pub mechanism: &'static str,
    /// Where it was written, when it is a file.
    pub path: Option<PathBuf>,
    /// Anything that worked less well than it should have.
    pub warnings: Vec<String>,
}

/// Registers the supervisor to start at logon, and starts it now.
///
/// `home` is passed through to the daemon rather than left to the environment.
/// A service inherits the environment of whatever started it — the launchd
/// bootstrap context, the Task Scheduler — not the shell that ran `ralon
/// install`, so a `RALON_HOME` that was set here would silently not apply there,
/// and the daemon would look after a different set of workspaces than the one
/// the developer just configured.
pub fn install(executable: &std::path::Path, home: &std::path::Path) -> Result<Registration> {
    platform::install(executable, home)
}

/// Removes the registration. `false` means there was none.
pub fn uninstall() -> Result<bool> {
    platform::uninstall()
}

/// Whether the registration currently exists.
pub fn installed() -> bool {
    platform::installed()
}

/// Why there is no supervisor here, for the platforms where there is not.
pub fn unsupported_reason() -> String {
    platform::unsupported_reason()
}
