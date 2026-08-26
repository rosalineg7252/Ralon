//! `chflags uchg` — the only thing on macOS that refuses a process nobody
//! started.
//!
//! ## This reverses an earlier decision, on purpose
//!
//! `enforce/unguarded.rs` used to cover macOS, and said of this mechanism: "a
//! narrowing of the same kind as the Windows deny ACE, not a guard, and it is
//! not implemented rather than being implemented and described as protection."
//!
//! The objection was to the description, not the mechanism, and it was right.
//! What changed is that `ralon install` needs *something* a background process
//! can apply to an agent it did not start, and on macOS this is the entire list:
//! Seatbelt is inherited and cannot be imposed, and Endpoint Security wants an
//! Apple-granted entitlement, root, and Full Disk Access — privileges that would
//! make Ralon a bigger risk than the thing it protects against.
//!
//! So it is implemented, and described as exactly what it is:
//!
//! - It is a **narrowing, not a boundary.** `chflags nouchg` undoes it, needs no
//!   privileges, and is available to the agent. An agent that goes looking for a
//!   way through will find one.
//! - It is **not process-level sandboxing** and is not equivalent to `ralon run`.
//!   `run` applies a Seatbelt profile that the agent cannot drop, cannot see, and
//!   cannot ask the kernel to lift. This is a bit in an inode.
//! - It **does not pin unprotected ancestors.** A protected file stays immutable
//!   if a directory above it is renamed, but the *path* the policy named no
//!   longer refers to it. Making every ancestor immutable would close that and
//!   stop the project having any new files written anywhere in it, which is not
//!   a trade worth making silently.
//!
//!   A protected *directory* is not subject to this: it carries the flag itself,
//!   and an immutable directory cannot be renamed or removed. That is stronger
//!   than this file first claimed — the macOS CI job caught the overstatement by
//!   failing a test that asserted the rename succeeded.
//!
//! What it does buy is real, and is why it beats nothing: every ordinary write
//! fails. Editors, `>` redirects, `rm`, `mv`, `sed -i`, every agent's edit tool,
//! and every shell command an agent runs are all refused with `EPERM`, for every
//! process on the machine, whether or not it has heard of Ralon. That is the same
//! bargain the Windows deny ACE makes, and it is stated in `security.md` in these
//! words.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Set on paths the policy protects; cleared when enforcement is released.
///
/// The *user* immutable flag, not the system one: `SF_IMMUTABLE` needs root to
/// set and a boot into single-user mode to clear, which would turn a mistake in
/// a policy file into a support call.
/// `u32`, not `c_ulong`: on macOS `st_flags` is a `u32` and `chflags` takes one.
/// Spelled `c_ulong` here originally, which compiled everywhere except macOS.
const UF_IMMUTABLE: u32 = 0x0000_0002;

/// Whether `path` currently refuses writes.
pub fn is_set(path: &Path) -> bool {
    flags(path).is_some_and(|current| current & UF_IMMUTABLE != 0)
}

/// Makes `path` immutable. `Err` carries the `errno`.
pub fn set(path: &Path) -> Result<(), i32> {
    let current = flags(path).ok_or(libc::ENOENT)?;
    change(path, current | UF_IMMUTABLE)
}

/// Gives `path` back. Other flags on the inode are left as they were.
pub fn clear(path: &Path) -> Result<(), i32> {
    let current = flags(path).ok_or(libc::ENOENT)?;
    change(path, current & !UF_IMMUTABLE)
}

/// Everything under `root` that has to carry the flag, deepest first.
///
/// A directory's own flag stops entries being added to or removed from it, and
/// says nothing about the contents of the files already inside — so each of
/// those is flagged in its own right, the same reason the Windows backend locks
/// every file inside a protected directory rather than just the directory.
///
/// Deepest first so that [`set`] reaches the children before the parent becomes
/// immutable. `chflags` on a child alters the child's inode rather than the
/// parent's directory entry, so it would work in either order; doing it in the
/// order that would still work if that were not true costs nothing.
pub fn targets(root: &Path) -> Vec<PathBuf> {
    let Ok(metadata) = std::fs::symlink_metadata(root) else {
        return Vec::new();
    };
    if !metadata.is_dir() {
        return vec![root.to_path_buf()];
    }

    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    let mut directories = Vec::new();

    while let Some(directory) = pending.pop() {
        directories.push(directory.clone());
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                pending.push(entry.path());
            } else {
                // Symlinks included: `chflags` acts on the link itself, so this
                // stops the link being repointed at something else, which is
                // the only thing about it Ralon can protect.
                found.push(entry.path());
            }
        }
    }

    directories.reverse();
    found.extend(directories);
    found
}

fn flags(path: &Path) -> Option<u32> {
    let Ok(name) = CString::new(path.as_os_str().as_bytes()) else {
        return None;
    };
    // Safety: `stat` is zeroed before use and `name` outlives the call.
    let mut data: libc::stat = unsafe { std::mem::zeroed() };
    // `lstat`, so a symlink's own flags are read rather than its target's.
    if unsafe { libc::lstat(name.as_ptr(), &mut data) } != 0 {
        return None;
    }
    Some(data.st_flags)
}

fn change(path: &Path, flags: u32) -> Result<(), i32> {
    let name = CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
    // Safety: `name` is NUL-terminated and outlives the call.
    if unsafe { libc::chflags(name.as_ptr(), flags) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EPERM))
    }
}

/// Why a path could not be made immutable, in words rather than a number.
pub fn explain(path: &Path, errno: i32) -> String {
    let detail = match errno {
        libc::EPERM => "it belongs to another user, so only its owner or root can flag it",
        libc::EROFS => "it is on a read-only filesystem",
        libc::ENOTSUP => "this filesystem does not support file flags",
        libc::ENOENT => "it went away while enforcement was being applied",
        _ => "the filesystem refused",
    };
    format!(
        "{} is not protected — {detail} (errno {errno})",
        path.display()
    )
}
