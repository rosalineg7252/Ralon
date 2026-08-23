//! Linux enforcement backends.
//!
//! Both backends restrict the *current* process and then `exec` the target
//! command: Landlock domains and namespaces are inherited across `exec` and by
//! every descendant, and neither can be dropped once entered. There is no
//! supervisor process to bypass or kill.

use std::ffi::{CString, OsString};
use std::io;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;

use anyhow::{anyhow, bail, Context, Result};
use landlock::{
    path_beneath_rules, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};

use super::carve::Carve;
use super::{Availability, Backend, Plan};

/// The last Landlock ABI whose write set means exactly "modify a file". Later
/// ABIs add device ioctls (v5) and unix socket connects (v9), which a policy
/// about file contents has no business denying. Older kernels are handled by
/// `CompatLevel::BestEffort`.
const LANDLOCK_ABI: ABI = ABI::V3;

pub fn enforce_and_exec(plan: &Plan, command: &[OsString]) -> anyhow::Error {
    let applied = match plan.backend {
        Backend::Mount => apply_mount(&plan.pinned, &plan.protected),
        Backend::Landlock => match &plan.carve {
            Some(carve) => apply_landlock(carve),
            None => Err(anyhow!("internal error: landlock plan was not built")),
        },
        Backend::Auto => Err(anyhow!("internal error: backend was not resolved")),
    };
    if let Err(error) = applied {
        return error;
    }
    exec(command)
}

/// Replaces this process with `command`.
fn exec(command: &[OsString]) -> anyhow::Error {
    let Some((program, arguments)) = command.split_first() else {
        return anyhow!("no command given");
    };
    let error = Command::new(program).args(arguments).exec();
    anyhow::Error::new(error).context(format!("failed to run `{}`", program.to_string_lossy()))
}

// ---------------------------------------------------------------------------
// mount backend
// ---------------------------------------------------------------------------

pub fn mount_availability() -> Availability {
    // Enforcement needs *two* nested user namespaces: one to mount in, and a
    // second one to lock those mounts. A host can allow the first and refuse
    // the second, so probing only the first would advertise a backend that
    // fails halfway through, after the policy was reported as enforced. Do
    // exactly what `apply_mount` does instead — in a child process, so the
    // probe cannot affect this one.
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

fn apply_mount(pinned: &[PathBuf], protected: &[PathBuf]) -> Result<()> {
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

/// The mount flags a user namespace will not let a remount clear.
fn locked_flags(target: &CString) -> Result<libc::c_ulong> {
    let mut stats: libc::statvfs = unsafe { mem::zeroed() };
    check(unsafe { libc::statvfs(target.as_ptr(), &mut stats) })
        .context("failed to read mount flags")?;

    // ST_* and MS_* are different numbering schemes; ST_RELATIME and MS_BIND
    // even share a value. Translate explicitly.
    let pairs = [
        (libc::ST_NOSUID, libc::MS_NOSUID),
        (libc::ST_NODEV, libc::MS_NODEV),
        (libc::ST_NOEXEC, libc::MS_NOEXEC),
        (libc::ST_NOATIME, libc::MS_NOATIME),
        (libc::ST_NODIRATIME, libc::MS_NODIRATIME),
        (libc::ST_RELATIME, libc::MS_RELATIME),
    ];
    Ok(pairs.iter().fold(0, |flags, (present, wanted)| {
        if stats.f_flag & present != 0 {
            flags | wanted
        } else {
            flags
        }
    }))
}

// ---------------------------------------------------------------------------
// landlock backend
// ---------------------------------------------------------------------------

pub fn landlock_availability() -> Availability {
    match landlock_abi() {
        Some(abi) if abi >= 2 => Availability::Available {
            detail: format!("kernel ABI v{abi}"),
        },
        Some(abi) => Availability::Available {
            detail: format!("kernel ABI v{abi}, no cross-directory renames"),
        },
        None => Availability::Unavailable {
            reason: "the kernel reports no Landlock support (needs Linux 5.13+ with landlock \
                     enabled, e.g. lsm=landlock,... on the kernel command line)"
                .to_string(),
        },
    }
}

fn landlock_abi() -> Option<i64> {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    let version = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    (version > 0).then_some(version)
}

fn apply_landlock(carve: &Carve) -> Result<()> {
    if carve.restricted.is_empty() {
        return Ok(());
    }

    let access = AccessFs::from_write(LANDLOCK_ABI);
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(access)?
        .create()?
        .no_new_privs(true)
        .add_rules(path_beneath_rules(&carve.granted, access))?
        .restrict_self()?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::PartiallyEnforced => {
            eprintln!(
                "ralon: warning: this kernel supports only part of the policy; \
                 run `ralon status` for details"
            );
            Ok(())
        }
        RulesetStatus::NotEnforced => {
            bail!("the kernel accepted no part of the policy — nothing is protected")
        }
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("path contains a null byte: {}", path.display()))
}

fn check(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Runs `action` in a forked child and reports its errno.
///
/// The child only sets up namespaces for itself and exits, so nothing it does
/// is visible here. This assumes a single-threaded caller, which the binary is.
fn probe(action: impl Fn() -> io::Result<()>) -> io::Result<()> {
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            let errno = match action() {
                Ok(()) => 0,
                Err(error) => error.raw_os_error().unwrap_or(1),
            };
            unsafe { libc::_exit(errno.clamp(0, 126)) }
        }
        child => {
            let mut status = 0;
            if unsafe { libc::waitpid(child, &mut status, 0) } == -1 {
                return Err(io::Error::last_os_error());
            }
            match libc::WEXITSTATUS(status) {
                0 => Ok(()),
                errno => Err(io::Error::from_raw_os_error(errno)),
            }
        }
    }
}
