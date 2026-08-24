//! Read-only bind mounts in a locked namespace.
//!
//! Precise, in the sense that only the paths the policy names behave
//! differently. The privileges to mount, and a mount tree the host never sees,
//! both come from the user namespace this enters.

use std::ffi::CString;
use std::io;
use std::mem;
use std::path::{Path, PathBuf};
use std::ptr;

use anyhow::{Context, Result};

use super::sys::{check, cstring, probe};
use crate::enforce::Availability;

pub fn availability() -> Availability {
    // Enforcement needs *two* nested user namespaces: one to mount in, and a
    // second one to lock those mounts. A host can allow the first and refuse
    // the second, so probing only the first would advertise a backend that
    // fails halfway through, after the policy was reported as enforced. Do
    // exactly what `apply` does instead — in a child process, so the probe
    // cannot affect this one.
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    match probe(|| {
        enter_namespaces(uid, gid)?;
        enter_namespaces(uid, gid)
    }) {
        Ok(()) => Availability::Available {
            detail: "read-only bind mounts in a locked namespace".to_string(),
        },
        Err(error) => Availability::Unavailable {
            reason: format!("unprivileged user namespaces are not usable ({error})"),
        },
    }
}

pub fn apply(pinned: &[PathBuf], protected: &[PathBuf]) -> Result<()> {
    if protected.is_empty() {
        return Ok(());
    }

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    enter_namespaces(uid, gid).context("failed to create a user and mount namespace")?;

    // Keep every mount we make out of the host's mount tree.
    check(unsafe {
        libc::mount(
            ptr::null(),
            c"/".as_ptr(),
            ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            ptr::null(),
        )
    })
    .context("failed to make the mount tree private")?;

    // Parents first: a bind mount of a directory does not carry the mounts
    // already inside it, so pinning a parent afterwards would hide them.
    for path in pinned {
        bind(path).with_context(|| format!("failed to pin {}", path.display()))?;
    }
    for path in protected {
        bind_read_only(path)?;
    }

    // The working directory still points into the mounts that were there
    // before, and relative lookups through it would walk straight past
    // everything just mounted. Re-entering it resolves it against the new tree.
    if let Ok(directory) = std::env::current_dir() {
        std::env::set_current_dir(&directory).with_context(|| {
            format!("failed to re-enter {} after mounting", directory.display())
        })?;
    }

    // Entering a *fresh* user namespace locks the mounts inherited from the old
    // one: the kernel then refuses both `umount` and any bind mount that would
    // reveal what is underneath them. Without this second step the sandboxed
    // process could simply unmount its way out.
    enter_namespaces(uid, gid).context("failed to lock the mount namespace")?;

    Ok(())
}

/// Returns `io::Result` so the availability probe can report the errno.
fn enter_namespaces(uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
    check(unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) })?;

    // Map our own ids onto themselves so the sandboxed program keeps the
    // identity it was started with instead of turning into `nobody`.
    // setgroups must be denied before gid_map may be written.
    let _ = std::fs::write("/proc/self/setgroups", "deny");
    std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1"))?;
    std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1"))?;
    Ok(())
}

/// Mounts `path` onto itself, leaving its access rights alone. The point is the
/// mount point: the kernel will not rename or remove one.
fn bind(path: &Path) -> Result<()> {
    let target = cstring(path)?;
    check(unsafe {
        libc::mount(
            target.as_ptr(),
            target.as_ptr(),
            ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            ptr::null(),
        )
    })
    .with_context(|| format!("failed to bind mount {}", path.display()))
}

fn bind_read_only(path: &Path) -> Result<()> {
    bind(path)?;
    let target = cstring(path)?;

    if mount_setattr_read_only(&target).is_ok() {
        return Ok(());
    }

    // Before Linux 5.12 there is no mount_setattr, so fall back to a classic
    // read-only remount. It must repeat the flags the kernel locks inside a
    // user namespace, or it is rejected.
    let flags = libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | locked_flags(&target)?;
    check(unsafe {
        libc::mount(
            ptr::null(),
            target.as_ptr(),
            ptr::null(),
            flags,
            ptr::null(),
        )
    })
    .with_context(|| format!("failed to remount {} read-only", path.display()))
}

#[repr(C)]
#[derive(Default)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// Linux 5.12+. Unlike a remount this applies to submounts too, so a mount
/// inside a protected directory cannot stay writable.
fn mount_setattr_read_only(target: &CString) -> io::Result<()> {
    const MOUNT_ATTR_RDONLY: u64 = 0x1;
    const AT_RECURSIVE: libc::c_int = 0x8000;

    let attributes = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY,
        ..MountAttr::default()
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            target.as_ptr(),
            AT_RECURSIVE,
            &attributes as *const MountAttr,
            mem::size_of::<MountAttr>(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// `statvfs` flags, as the kernel reports them in `f_flags`. Spelled out here
// rather than taken from libc, which only defines them for glibc — the musl
// builds we ship do not compile against `libc::ST_*`.
const ST_NOSUID: libc::c_ulong = 0x0002;
const ST_NODEV: libc::c_ulong = 0x0004;
const ST_NOEXEC: libc::c_ulong = 0x0008;
const ST_NOATIME: libc::c_ulong = 0x0400;
const ST_NODIRATIME: libc::c_ulong = 0x0800;
const ST_RELATIME: libc::c_ulong = 0x1000;

/// The mount flags a user namespace will not let a remount clear.
fn locked_flags(target: &CString) -> Result<libc::c_ulong> {
    let mut stats: libc::statvfs = unsafe { mem::zeroed() };
    check(unsafe { libc::statvfs(target.as_ptr(), &mut stats) })
        .context("failed to read mount flags")?;

    // ST_* and MS_* are different numbering schemes; ST_RELATIME and MS_BIND
    // even share a value. Translate explicitly.
    let pairs = [
        (ST_NOSUID, libc::MS_NOSUID),
        (ST_NODEV, libc::MS_NODEV),
        (ST_NOEXEC, libc::MS_NOEXEC),
        (ST_NOATIME, libc::MS_NOATIME),
        (ST_NODIRATIME, libc::MS_NODIRATIME),
        (ST_RELATIME, libc::MS_RELATIME),
    ];
    Ok(pairs.iter().fold(0, |flags, (present, wanted)| {
        if stats.f_flag & present != 0 {
            flags | wanted
        } else {
            flags
        }
    }))
}
