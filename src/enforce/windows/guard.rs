//! Holding a policy open with no command to supervise.
//!
//! `run` protects the agent it starts. A guard protects the agents it does
//! *not* start — every one of them, including the editor you already had open
//! and the tool you install next month, because a share-mode lock is refused to
//! every process on the machine and asks nothing of the process it refuses.
//! Start one and the project is protected until it is stopped, with no wrapper
//! command anywhere.
//!
//! What it gives up in exchange is inheritance. `run` on Linux *becomes* the
//! command, so there is nothing left to kill; a guard is a process, and killing
//! it releases the locks. It cannot use `run`'s job object either, since it has
//! no child to put in one. So this is the weaker of the two in exactly one way,
//! and the stronger in the way that matters most of the time.
//!
//! Two guards for the same project would each try to lock the same files and
//! the second would lose, so they rendezvous through a named event: creating it
//! is how a guard claims the project, waiting on it is how it parks, and
//! signalling it is how `--stop` asks for a clean release. It is an object in
//! the kernel rather than a pid file, so a guard that dies takes its claim with
//! it and leaves nothing to go stale.

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicPtr, Ordering};

use anyhow::{Context, Result};

use super::{acl, locks};
use crate::enforce::Plan;

/// Whether this platform can protect a process it did not start.
pub const AVAILABLE: bool = true;

const INFINITE: u32 = 0xFFFF_FFFF;
const EVENT_MODIFY_STATE: u32 = 0x0002;
const SYNCHRONIZE: u32 = 0x0010_0000;
const ERROR_ALREADY_EXISTS: u32 = 183;
const TRUE: i32 = 1;
const FALSE: i32 = 0;

/// Detach the guard from this console so it outlives the shell that started it.
const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

/// Matches `job.rs`: one spelling of `HANDLE` for the whole backend.
type Handle = *mut c_void;

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    reserved2_length: u16,
    reserved2: *mut u8,
    std_input: Handle,
    std_output: Handle,
    std_error: Handle,
}

#[repr(C)]
struct ProcessInformation {
    process: Handle,
    thread: Handle,
    process_id: u32,
    thread_id: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateEventW(
        attributes: *mut c_void,
        manual_reset: i32,
        initial_state: i32,
        name: *const u16,
    ) -> Handle;
    fn OpenEventW(desired_access: u32, inherit_handle: i32, name: *const u16) -> Handle;
    fn SetEvent(event: Handle) -> i32;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetLastError() -> u32;
    fn SetConsoleCtrlHandler(
        handler: Option<unsafe extern "system" fn(u32) -> i32>,
        add: i32,
    ) -> i32;
    #[allow(clippy::too_many_arguments)]
    fn CreateProcessW(
        application_name: *const u16,
        command_line: *mut u16,
        process_attributes: *mut c_void,
        thread_attributes: *mut c_void,
        inherit_handles: i32,
        creation_flags: u32,
        environment: *mut c_void,
        current_directory: *const u16,
        startup_information: *const StartupInfoW,
        process_information: *mut ProcessInformation,
    ) -> i32;
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *mut c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template: *mut c_void,
    ) -> Handle;
    fn SetStdHandle(std_handle: u32, handle: Handle) -> i32;
}

/// The event the parked guard is waiting on, so Ctrl-C can release it the same
/// way `--stop` does instead of killing the process and leaving the ACL behind.
static PARKED_ON: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

unsafe extern "system" fn on_console_signal(_kind: u32) -> i32 {
    let event = PARKED_ON.load(Ordering::SeqCst);
    if event.is_null() {
        return FALSE;
    }
    unsafe { SetEvent(event) };
    // Handled: the wait returns, the locks are dropped in order, and the
    // process exits on its own terms rather than being torn down here.
    TRUE
}

/// A running guard: the locks, the ACL narrowing, and the claim on the project.
pub struct Session {
    event: Handle,
    locks: locks::Locks,
    narrowing: acl::Narrowing,
    /// Anything the caller should say out loud before parking.
    pub warnings: Vec<String>,
}

impl Session {
    pub fn files(&self) -> usize {
        self.locks.files
    }

    pub fn directories(&self) -> usize {
        self.locks.directories
    }

    pub fn refused_directories(&self) -> usize {
        self.narrowing.directories()
    }

    /// Blocks until someone asks for the locks back.
    pub fn park(self) -> Result<()> {
        PARKED_ON.store(self.event, Ordering::SeqCst);
        unsafe { SetConsoleCtrlHandler(Some(on_console_signal), TRUE) };

        unsafe { WaitForSingleObject(self.event, INFINITE) };

        PARKED_ON.store(std::ptr::null_mut(), Ordering::SeqCst);
        // `self` is dropped here, in declaration order: the claim is released
        // last, so nothing can take the project over while the locks are still
        // coming off.
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.event) };
    }
}

/// Takes the locks and claims the project.
pub fn start(root: &Path, plan: &Plan) -> Result<Session> {
    let name = event_name(root);
    let event = unsafe { CreateEventW(std::ptr::null_mut(), TRUE, FALSE, name.as_ptr()) };
    if event.is_null() {
        anyhow::bail!("could not claim this project (Windows error {})", unsafe {
            GetLastError()
        });
    }
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        unsafe { CloseHandle(event) };
        anyhow::bail!("a guard is already protecting this project — `ralon guard --stop` first");
    }

    // Taken in the same order as `run`, and for the same reason: if a path
    // cannot be locked, nothing is claimed to be protected.
    let locks = match locks::acquire(&plan.pinned, &plan.protected) {
        Ok(locks) => locks,
        Err(error) => {
            unsafe { CloseHandle(event) };
            return Err(error);
        }
    };
    let (narrowing, warnings) = acl::refuse_new_entries(&directories(&plan.protected));

    Ok(Session {
        event,
        locks,
        narrowing,
        warnings,
    })
}

/// Asks a running guard to release. `false` means there was none.
pub fn stop(root: &Path) -> Result<bool> {
    let name = event_name(root);
    let event = unsafe { OpenEventW(EVENT_MODIFY_STATE, FALSE, name.as_ptr()) };
    if event.is_null() {
        return Ok(false);
    }
    let signalled = unsafe { SetEvent(event) } != 0;
    unsafe { CloseHandle(event) };
    if !signalled {
        anyhow::bail!("found a guard but could not ask it to stop");
    }

    // Asking is not the same as having been let go. Waiting for the claim to
    // disappear means that when this returns, the files really are writable —
    // otherwise the next command in a script races the guard's own cleanup.
    for _ in 0..100 {
        if !running(root) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Ok(true)
}

/// Whether a guard currently holds this project.
pub fn running(root: &Path) -> bool {
    let name = event_name(root);
    let event = unsafe { OpenEventW(SYNCHRONIZE, FALSE, name.as_ptr()) };
    if event.is_null() {
        return false;
    }
    unsafe { CloseHandle(event) };
    true
}

/// Starts a guard that outlives this console, and waits to see it come up.
///
/// Reporting "started" for a process that died on its first syscall would be
/// the worst kind of lie this tool can tell, so the claim is what is waited
/// for, not the spawn.
///
/// `CreateProcess` rather than `std::process::Command`, for one reason:
/// inheritance is all or nothing. `Command` has to pass `bInheritHandles =
/// TRUE` to hand over stdio, and the child then inherits *every* inheritable
/// handle the shell gave this process — including the pipe a shell reads
/// output from. A guard holding that pipe open for the rest of the day means
/// `ralon guard --detach | anything` never finishes, long after every process
/// the shell is waiting on has exited. Observed, not theorised.
pub fn detach(root: &Path) -> Result<()> {
    let executable = std::env::current_exe().context("could not find the ralon executable")?;
    let mut command_line = wide(format!(
        "\"{}\" --dir \"{}\" guard --detached",
        executable.display(),
        root.display()
    ));

    let mut startup: StartupInfoW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<StartupInfoW>() as u32;
    let mut information: ProcessInformation = unsafe { std::mem::zeroed() };

    let started = unsafe {
        CreateProcessW(
            std::ptr::null(),
            command_line.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            FALSE, // inherit nothing at all
            DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            std::ptr::null_mut(),
            std::ptr::null(),
            &startup,
            &mut information,
        )
    };
    if started == 0 {
        anyhow::bail!(
            "could not start a background guard (Windows error {})",
            unsafe { GetLastError() }
        );
    }
    unsafe {
        CloseHandle(information.thread);
        CloseHandle(information.process);
    }

    for _ in 0..60 {
        if running(root) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    anyhow::bail!(
        "a background guard was started but never claimed the project — \
         run `ralon guard` in this terminal to see why"
    )
}

/// Points this process's standard handles at `NUL`.
///
/// A detached guard inherits no handles, so `GetStdHandle` gives it nothing to
/// write to — and Rust's `println!` *panics* when a write fails. A background
/// process that dies the first time it mentions a warning would be a guard
/// that stops guarding, so the handles are made real and pointed at nothing.
pub fn silence_standard_handles() {
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const OPEN_EXISTING: u32 = 3;
    const STD_INPUT: u32 = -10i32 as u32;
    const STD_OUTPUT: u32 = -11i32 as u32;
    const STD_ERROR: u32 = -12i32 as u32;

    let null = unsafe {
        CreateFileW(
            wide("NUL").as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if null.is_null() || null == (-1isize as Handle) {
        return;
    }
    for handle in [STD_INPUT, STD_OUTPUT, STD_ERROR] {
        unsafe { SetStdHandle(handle, null) };
    }
}

/// Protected paths that are directories, which are the ones with the gap a
/// handle cannot cover.
fn directories(protected: &[PathBuf]) -> Vec<PathBuf> {
    protected
        .iter()
        .filter(|path| path.is_dir())
        .cloned()
        .collect()
}

/// Leftover ACL narrowing from a guard that was killed before it could undo it.
pub fn leftovers(protected: &[PathBuf]) -> Vec<PathBuf> {
    acl::leftovers(&directories(protected))
}

/// Clears that leftover state.
pub fn clear_leftovers(protected: &[PathBuf]) -> Vec<PathBuf> {
    acl::clear(&directories(protected))
}

/// A name in the kernel's object namespace, one per project directory.
///
/// `Local\` scopes it to the logon session, which is the same boundary the
/// locks themselves have: a guard protects the desktop it is running on.
fn event_name(root: &Path) -> Vec<u16> {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in root.to_string_lossy().to_lowercase().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }

    wide(format!("Local\\ralon-guard-{hash:016x}"))
}

/// A NUL-terminated UTF-16 string, which is what every call here wants.
fn wide(text: impl AsRef<OsStr>) -> Vec<u16> {
    text.as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
