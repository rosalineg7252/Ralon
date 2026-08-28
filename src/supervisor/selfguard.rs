//! What the supervisor holds on to protect *itself*.
//!
//! Everything Ralon depends on between reboots lives in a directory the user can
//! write, because none of this asks for administrator. That is the right trade
//! — a tool that protects you from an agent should not be the reason a
//! privileged process exists for an agent to talk to — but it leaves two things
//! an agent could do without touching a single protected file:
//!
//! 1. **Replace the supervisor.** `%LOCALAPPDATA%\Ralon\bin\ralon.exe` is what
//!    the logon task runs. Move it aside, put something else at that name, and
//!    the next logon starts that instead. Nothing about the projects changed, so
//!    nothing reports anything.
//! 2. **Edit the scopes.** `config.yaml` is plain YAML. Delete one line and
//!    every repository under that scope stops being enforced at the next
//!    reconcile. There is no error, because as far as the supervisor is
//!    concerned it was told to stop looking there.
//!
//! Both are closed here, and by different mechanisms, because the platforms
//! differ in what they can promise:
//!
//! - **The binary** is held. On Windows an exclusive share-mode handle refuses
//!   every open, including the rename that a replace-in-place needs — the same
//!   mechanism the guards use, applied to Ralon's own file. On macOS it gets
//!   `chflags uchg`, the same narrowing `enforce/macos/immutable.rs` applies to
//!   a project, with the same limitation recorded there: an agent that thinks to
//!   run `chflags nouchg` undoes it.
//! - **The scopes** are held too, against writers but not readers, so anything
//!   editing `config.yaml` directly is refused while Ralon runs. `ralon scope
//!   add` still works: it asks the supervisor to stand down, writes, and starts
//!   it again — see `commands::with_the_supervisor_stopped`.
//!
//! This started as a fingerprint: hash the configuration, keep the hash in a
//! file only the supervisor can write, and report a mismatch. It was tested
//! against a real edit and it does not work, for a reason worth recording so
//! nobody rebuilds it. The supervisor watches `config.yaml` and reconciles
//! within a second of any write, and reconciling means *adopting* — so a
//! tampered config is re-fingerprinted almost immediately and then reports as
//! intact. A check that reliably goes green a second after the attack is worse
//! than no check, because it is quoted as evidence.
//!
//! What is *not* closed, and cannot be without contradicting a design decision
//! this project made on purpose: an agent that can run `ralon scope remove` can
//! remove a scope. There is no password and no approval step by design, so
//! anything running as you can use Ralon's own interface. That is the same
//! boundary that lets an agent kill a guard, and it is documented in
//! `security.md` rather than papered over. What is closed is the silent path —
//! editing the file directly, with nothing to notice it — and every change that
//! does go through Ralon is written to the log with what it was before.

use std::path::Path;

// Windows is the only platform that holds anything open here; macOS uses
// `chflags`, which needs no handle to stay applied.
#[cfg(windows)]
use anyhow::{Context, Result};
#[cfg(windows)]
use std::fs::File;

use super::registry;

/// The handles a running supervisor keeps for its own sake.
///
/// Dropping it releases them, which is correct: these protect a *running*
/// supervisor, and once it has exited there is nothing to protect.
pub struct Holdings {
    /// Never read. Holding them *is* the protection — the same reason
    /// `single::Claim` keeps a file it never touches.
    #[cfg(windows)]
    #[allow(dead_code)]
    held: Vec<File>,
    /// Reported by the caller rather than raised, so a supervisor never fails
    /// to start over its own hardening. Enforcing projects is the job; this is
    /// insurance on the job.
    pub warnings: Vec<String>,
}

/// Takes what can be taken. Never fails: anything that could not be held is a
/// warning, because refusing to supervise would be a worse outcome than
/// supervising without the extra protection.
pub fn hold(home: &Path) -> Holdings {
    // Linux has no supervisor, so there is nothing of Ralon's own to hold and
    // both of these go unused. The function still has to exist: `run()` is
    // compiled on every platform, and only the syscalls are gated.
    #[cfg(not(any(windows, target_os = "macos")))]
    let _ = home;

    #[cfg_attr(not(any(windows, target_os = "macos")), allow(unused_mut))]
    let mut warnings: Vec<String> = Vec::new();

    #[cfg(windows)]
    let mut held = Vec::new();

    #[cfg(windows)]
    {
        // Readers allowed, writers and deleters refused. Sharing *nothing* is
        // the obvious spelling and it is wrong in a way no unit test catches:
        // the supervisor launches every guard by running this same file, and
        // `CreateProcess` has to open the image to do it. Denying reads made the
        // daemon unable to start a single guard — `could not start a background
        // guard (Windows error 32)`, ERROR_SHARING_VIOLATION, against its own
        // binary — so a hardening measure turned into total loss of enforcement.
        // Found by watching a real install stop protecting anything.
        //
        // `FILE_SHARE_READ` still refuses the attack. Overwriting needs write
        // access; renaming aside and deleting both need delete access; none of
        // those are shared, so all three are refused while a reader — including
        // the loader — gets through.
        const FILE_SHARE_READ: u32 = 0x0000_0001;

        let binary = crate::service::stage::path(home);
        if binary.exists() {
            match open(&binary, FILE_SHARE_READ) {
                Ok(file) => held.push(file),
                Err(error) => warnings.push(format!(
                    "cannot hold {} ({error:#}); it could be replaced while Ralon runs",
                    binary.display()
                )),
            }
        }

        // The scopes, on the same terms: `ralon scope list` and every `status`
        // read this file, so denying reads would break the tool to protect it.
        let config = home.join(registry::CONFIG_FILE);
        if config.exists() {
            match open(&config, FILE_SHARE_READ) {
                Ok(file) => held.push(file),
                Err(error) => warnings.push(format!(
                    "cannot hold {} ({error:#}); a scope could be removed by editing it \
                     directly, which unprotects every project underneath",
                    config.display()
                )),
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let path = crate::service::stage::path(home);
        if path.exists() && !crate::enforce::immutable::is_set(&path) {
            if let Err(errno) = crate::enforce::immutable::set(&path) {
                warnings.push(format!(
                    "cannot protect {} ({}); it could be replaced while Ralon runs",
                    path.display(),
                    crate::enforce::immutable::explain(&path, errno)
                ));
            }
        }
    }

    Holdings {
        #[cfg(windows)]
        held,
        warnings,
    }
}

/// Opens `path` for reading with the given share mode, i.e. takes it away from
/// everyone else to the extent `share` allows.
#[cfg(windows)]
fn open(path: &Path, share: u32) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(share)
        .open(path)
        .with_context(|| format!("could not hold {}", path.display()))
}

/// Whether the scopes are protected from being edited behind Ralon's back.
///
/// Only ever false when the hold failed, which is a condition `status` should
/// mention rather than one anybody can act on directly. Not a tamper check —
/// see the note at the top of this file about why the fingerprint version of
/// this was removed instead of fixed.
pub fn scopes_are_held(home: &Path) -> bool {
    #[cfg(windows)]
    {
        if !super::single::running() {
            return false;
        }
        // Held means a writer is refused. Asking is opening for write and
        // seeing what happens, which is safe: on success nothing was written.
        std::fs::OpenOptions::new()
            .write(true)
            .open(home.join(registry::CONFIG_FILE))
            .is_err()
    }
    #[cfg(not(windows))]
    {
        let _ = home;
        false
    }
}

/// Appends a scope change to the supervisor's log.
///
/// Written by the command that makes the change rather than by the supervisor
/// that notices it, because with `config.yaml` held the supervisor never sees a
/// transition: the file can only be written while it is stopped, so it starts
/// up already agreeing with whatever is there. That is the right trade — the
/// change is prevented rather than observed — but it leaves this as the only
/// place the history can be recorded.
///
/// Adding a scope is unremarkable. Removing one stops every project underneath
/// being enforced, which nothing else writes down anywhere.
pub fn log_scope_change(home: &Path, before: &[std::path::PathBuf], after: &[std::path::PathBuf]) {
    use std::io::Write;

    if before == after {
        return;
    }
    let list = |roots: &[std::path::PathBuf]| {
        if roots.is_empty() {
            "none".to_string()
        } else {
            roots
                .iter()
                .map(|root| registry::display(root))
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    let Ok(mut log) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(home.join("supervisor.log"))
    else {
        return;
    };
    let _ = writeln!(
        log,
        "{}  scopes changed by `ralon`: {} -> {}",
        registry::timestamp(registry::now()),
        list(before),
        list(after)
    );
}

/// Clears whatever `hold` applied that outlives the process.
///
/// Only macOS has any: a Windows handle goes when the process does, but
/// `chflags uchg` is on the disk and would otherwise make the file impossible
/// to remove or upgrade.
pub fn release(home: &Path) {
    let _ = home;
    #[cfg(target_os = "macos")]
    {
        let path = crate::service::stage::path(home);
        if crate::enforce::immutable::is_set(&path) {
            let _ = crate::enforce::immutable::clear(&path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("ralon-selfguard-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn holding_refuses_a_direct_edit_of_the_scopes() {
        // The attack this closes: a scope deleted by writing config.yaml
        // directly unprotects every project under it, and reconciliation
        // treats that as an instruction rather than as tampering.
        let home = scratch("scopes");
        let config = home.join(registry::CONFIG_FILE);
        std::fs::write(&config, "roots:\n- D:\\projects\n").unwrap();

        let holdings = hold(&home);
        assert!(holdings.warnings.is_empty(), "{:?}", holdings.warnings);

        if cfg!(windows) {
            assert!(
                std::fs::write(&config, "roots: []\n").is_err(),
                "a scope could be removed by editing the file directly"
            );
            // Reading has to keep working: `scope list` and `status` both do it.
            assert!(std::fs::read_to_string(home.join(registry::CONFIG_FILE)).is_ok());
        }

        drop(holdings);
        // And once the supervisor is gone the file is ordinary again, because
        // this protects a running supervisor and nothing else.
        assert!(std::fs::write(&config, "roots: []\n").is_ok());
    }

    #[test]
    fn holding_refuses_a_replacement_of_the_binary() {
        let home = scratch("binary");
        let staged = crate::service::stage::path(&home);
        std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
        std::fs::write(&staged, b"the supervisor").unwrap();

        let holdings = hold(&home);
        if cfg!(windows) {
            assert!(
                std::fs::write(&staged, b"something else").is_err(),
                "the supervisor binary could be replaced while it runs"
            );
            assert!(
                std::fs::rename(&staged, staged.with_extension("old")).is_err(),
                "the supervisor binary could be renamed aside and substituted"
            );
            assert!(
                std::fs::remove_file(&staged).is_err(),
                "the supervisor binary could be deleted while it runs"
            );
            // And it must still be *readable*, which is not a nicety: the
            // supervisor starts every guard by running this file, and
            // `CreateProcess` opens the image to do it. Holding it with no
            // sharing at all passed both assertions above and left the daemon
            // unable to enforce anything — the hardening cost the whole
            // guarantee, and only a running install showed it.
            assert!(
                std::fs::File::open(&staged).is_ok(),
                "the supervisor cannot launch a guard from its own binary"
            );
        }
        drop(holdings);
    }

    #[test]
    fn nothing_is_held_when_there_is_nothing_to_hold() {
        // A state directory with neither file yet — the first `install` — must
        // not warn about failing to protect files that do not exist.
        let home = scratch("empty");
        assert!(hold(&home).warnings.is_empty());
    }
}
