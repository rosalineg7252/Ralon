//! The copy of the executable that the service actually runs.
//!
//! `ralon install` used to register the binary where it found itself, which on
//! a machine that installed Ralon from a package manager is inside that package
//! manager's directory — `node_modules/@stoneware-dev/win32-x64/bin/ralon.exe`,
//! `~/.cargo/bin/ralon.exe`, a virtualenv's `Scripts/`. Two things go wrong,
//! and both were reported by the same person on the same afternoon:
//!
//! 1. Windows will not delete the image of a running process. The supervisor
//!    runs from logon to logoff, so `bun remove`, `pip uninstall` and `cargo
//!    install --force` all fail on a file the package manager is certain it
//!    owns. The error names a permission problem rather than a running process,
//!    so the way out — Task Manager, then delete the directory by hand — is not
//!    one anybody is going to guess.
//! 2. Uninstalling the package leaves the registration behind, now pointing at
//!    a path that no longer exists. Task Scheduler keeps it, tries it at every
//!    logon, and fails silently forever.
//!
//! Copying the binary into Ralon's own state directory and registering *that*
//! path fixes both. The package manager's copy is never opened, so it is never
//! locked and uninstalling works normally; and the registration points
//! somewhere only `ralon uninstall` removes. It also makes upgrades work the
//! way people expect: the supervisor keeps running the version it started with
//! until it is restarted, rather than being tied to a file another tool is in
//! the middle of replacing.
//!
//! The copy is not a security boundary. It sits in a directory the user can
//! write, which is the same as everywhere else the binary could live — an agent
//! that can write `~/.cargo/bin` can write this too. What it is, is a place
//! nothing *else* rewrites on its own schedule.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Where the staged binary lives, under the state directory so `RALON_HOME`
/// moves it and a test can put it somewhere harmless.
pub fn path(home: &Path) -> PathBuf {
    let name = if cfg!(windows) { "ralon.exe" } else { "ralon" };
    home.join("bin").join(name)
}

/// Copies `executable` into the state directory and returns the copy.
///
/// Returns the path unchanged when it is already the staged copy: re-running
/// `install` from the staged binary — which is what the daemon's own restart
/// path does — must not try to copy a file onto itself.
pub fn install(executable: &Path, home: &Path) -> Result<PathBuf> {
    let staged = path(home);
    if same_file(executable, &staged) {
        return Ok(staged);
    }

    let directory = staged.parent().expect("staged path always has a parent");
    std::fs::create_dir_all(directory)
        .with_context(|| format!("failed to create {}", directory.display()))?;

    // A supervisor may be running from the file being replaced, and Windows
    // refuses to overwrite the image of a running process — but it does allow
    // the file to be renamed out of the way, which is the whole trick behind
    // every self-updating program on the platform. The old copy keeps running
    // under its new name until it exits, and `sweep` clears it next time.
    if staged.exists() && std::fs::copy(executable, &staged).is_err() {
        let aside = directory.join(format!("{}.old-{}", file_name(&staged), std::process::id()));
        std::fs::rename(&staged, &aside).with_context(|| {
            format!(
                "{} is in use and could not be moved aside — stop the supervisor \
                 with `ralon uninstall` and try again",
                staged.display()
            )
        })?;
    }

    std::fs::copy(executable, &staged).with_context(|| {
        format!(
            "failed to copy {} to {}",
            executable.display(),
            staged.display()
        )
    })?;

    // GitHub Actions artifacts and `fs::copy` between filesystems have both
    // produced a non-executable copy before. Cheap to assert, silent to skip.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755));
    }

    sweep(directory);
    Ok(staged)
}

/// Removes the staged copy. `Ok(false)` means there was none.
///
/// A failure here is reported rather than swallowed: the caller has just
/// deregistered the service, and a copy left behind with nothing pointing at it
/// is clutter — but a copy left behind *because it is still running* means the
/// uninstall did not finish, and that is worth saying out loud.
pub fn remove(home: &Path) -> Result<bool> {
    let staged = path(home);
    if !staged.exists() {
        sweep(staged.parent().unwrap_or(home));
        return Ok(false);
    }
    std::fs::remove_file(&staged).with_context(|| {
        format!(
            "failed to remove {} — a supervisor may still be running from it",
            staged.display()
        )
    })?;
    sweep(staged.parent().unwrap_or(home));
    Ok(true)
}

/// Deletes the `.old-*` copies left by earlier upgrades, ignoring the ones
/// still running. Best effort by design — this is tidying, not correctness.
fn sweep(directory: &Path) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.contains(".old-") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "ralon".into())
}

/// Whether two paths are the same file on disk.
///
/// Compared after canonicalization rather than as written: the staged path is
/// built from `home`, which may have been given as a relative path or reached
/// through a junction, and `current_exe` is always absolute and resolved.
fn same_file(left: &Path, right: &Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!("ralon-stage-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn the_registered_path_is_never_the_one_the_package_manager_owns() {
        let scratch = scratch("owned");
        let package = scratch.join("node_modules");
        std::fs::create_dir_all(&package).unwrap();
        let source = package.join(if cfg!(windows) { "ralon.exe" } else { "ralon" });
        std::fs::write(&source, b"binary").unwrap();

        let home = scratch.join("home");
        let staged = install(&source, &home).unwrap();

        // The point of the whole module: what gets registered is under Ralon's
        // own state directory, so uninstalling the package cannot break it and
        // a running supervisor cannot block the package's removal.
        assert!(staged.starts_with(&home), "{}", staged.display());
        assert!(!staged.starts_with(&package), "{}", staged.display());
        assert_eq!(std::fs::read(&staged).unwrap(), b"binary");
        // And the original is untouched and still deletable.
        std::fs::remove_file(&source).unwrap();
    }

    #[test]
    fn installing_from_the_staged_copy_is_not_a_copy_onto_itself() {
        let scratch = scratch("self");
        let home = scratch.join("home");
        let source = scratch.join(if cfg!(windows) { "ralon.exe" } else { "ralon" });
        std::fs::write(&source, b"binary").unwrap();

        let staged = install(&source, &home).unwrap();
        let again = install(&staged, &home).unwrap();

        assert_eq!(staged, again);
        assert_eq!(std::fs::read(&again).unwrap(), b"binary");
    }

    #[test]
    fn a_second_install_replaces_the_copy() {
        let scratch = scratch("upgrade");
        let home = scratch.join("home");
        let source = scratch.join(if cfg!(windows) { "ralon.exe" } else { "ralon" });

        std::fs::write(&source, b"v1").unwrap();
        install(&source, &home).unwrap();
        std::fs::write(&source, b"v2").unwrap();
        let staged = install(&source, &home).unwrap();

        assert_eq!(std::fs::read(&staged).unwrap(), b"v2");
    }

    #[test]
    fn removing_reports_whether_there_was_anything_to_remove() {
        let scratch = scratch("remove");
        let home = scratch.join("home");
        let source = scratch.join(if cfg!(windows) { "ralon.exe" } else { "ralon" });
        std::fs::write(&source, b"binary").unwrap();

        assert!(!remove(&home).unwrap());
        install(&source, &home).unwrap();
        assert!(remove(&home).unwrap());
        assert!(!path(&home).exists());
    }

    #[test]
    fn superseded_copies_do_not_accumulate() {
        let scratch = scratch("sweep");
        let home = scratch.join("home");
        let source = scratch.join(if cfg!(windows) { "ralon.exe" } else { "ralon" });
        std::fs::write(&source, b"binary").unwrap();
        let staged = install(&source, &home).unwrap();

        let directory = staged.parent().unwrap();
        std::fs::write(directory.join("ralon.exe.old-1234"), b"stale").unwrap();
        install(&source, &home).unwrap();

        assert!(!directory.join("ralon.exe.old-1234").exists());
    }
}
