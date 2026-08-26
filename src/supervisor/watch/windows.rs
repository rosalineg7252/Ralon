//! `ReadDirectoryChangesW`, one recursive registration per scan root.
//!
//! The synchronous form, on a thread per root, rather than overlapped I/O and a
//! completion port. The asynchronous version exists to let one thread service
//! many directories; there are as many threads here as the developer has code
//! directories — typically one — and each spends its life blocked in a syscall.
//! Overlapped I/O would buy nothing and cost a state machine.
//!
//! Blocking does mean a thread cannot be asked to stop, only interrupted, so
//! `Drop` cancels the pending read with `CancelIoEx` and closes the handle. A
//! supervisor normally runs until the machine goes down and would not care; the
//! tests create and drop watchers, and a leaked thread blocked on a directory
//! that is being deleted is how a test suite starts hanging on Windows.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

use anyhow::Result;

use super::Watcher;

type Handle = *mut c_void;

const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// Names appearing and disappearing is the whole question — `agent.lock` is
/// there or it is not. `LAST_WRITE` is included so that editing a policy in
/// place is noticed too, since that changes what should be enforced.
const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x0000_0001;
const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x0000_0002;
const FILE_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x0000_0010;
const FILTER: u32 =
    FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE;

/// 64 KB, the documented ceiling for a network share and comfortably more than
/// a local one needs. A read that overflows it returns zero bytes with the
/// changes lost — which the sweep behind this exists to survive.
const BUFFER: usize = 64 * 1024;

#[repr(C)]
struct FileNotifyInformation {
    next_entry_offset: u32,
    action: u32,
    file_name_length: u32,
    // followed by `file_name_length` bytes of UTF-16
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *mut c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template: *mut c_void,
    ) -> Handle;
    fn ReadDirectoryChangesW(
        directory: Handle,
        buffer: *mut c_void,
        buffer_length: u32,
        watch_subtree: i32,
        filter: u32,
        bytes_returned: *mut u32,
        overlapped: *mut c_void,
        completion: *mut c_void,
    ) -> i32;
    fn CancelIoEx(handle: Handle, overlapped: *mut c_void) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetLastError() -> u32;
}

/// A raw handle that may cross a thread boundary.
///
/// Safety: a Win32 `HANDLE` is a process-wide kernel object reference with no
/// thread affinity. The pointer is `!Send` only because it is a pointer.
struct Shared(Handle);
unsafe impl Send for Shared {}

pub struct Directories {
    /// Kept only to cancel and close. `Shared` rather than the raw handle
    /// because each one is also held by a watcher thread, which is what makes
    /// crossing threads with it correct in the first place.
    handles: Vec<Shared>,
    receiver: Receiver<PathBuf>,
    roots: Vec<PathBuf>,
}

impl Drop for Directories {
    fn drop(&mut self) {
        for handle in &self.handles {
            // Unblocks the thread's `ReadDirectoryChangesW`, which then sees a
            // closed handle and returns.
            unsafe { CancelIoEx(handle.0, std::ptr::null_mut()) };
            unsafe { CloseHandle(handle.0) };
        }
    }
}

impl Watcher for Directories {
    fn changes(&mut self, timeout: Duration) -> Vec<PathBuf> {
        let mut changed = Vec::new();
        match self.receiver.recv_timeout(timeout) {
            Ok(path) => changed.push(path),
            Err(RecvTimeoutError::Timeout) => return changed,
            // Every watcher thread is gone. Reporting nothing turns each wait
            // into the sweep interval, which is the degraded-but-correct state
            // rather than a spin.
            Err(RecvTimeoutError::Disconnected) => {
                std::thread::sleep(timeout);
                return changed;
            }
        }
        // One notification usually means several. Draining what has already
        // arrived collapses a checkout of a thousand files into one pass.
        while let Ok(path) = self.receiver.try_recv() {
            changed.push(path);
        }
        changed
    }

    fn describe(&self) -> String {
        format!(
            "enforcement starts on a new policy in {} (ReadDirectoryChangesW)",
            self.roots
                .iter()
                .map(|root| crate::supervisor::registry::display(root))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

pub fn start(roots: &[PathBuf]) -> Result<Directories> {
    let (sender, receiver) = mpsc::channel();
    let mut handles = Vec::new();
    let mut watched = Vec::new();

    for root in roots {
        let handle = match open(root) {
            Some(handle) => handle,
            // One unreadable root is not a reason to have no watcher at all;
            // the sweep still covers it, and `describe` reports what is
            // actually being watched rather than what was asked for.
            None => continue,
        };
        handles.push(Shared(handle));
        watched.push(root.clone());

        let shared = Shared(handle);
        let sender = sender.clone();
        let root = root.clone();
        std::thread::Builder::new()
            .name("ralon-watch".to_string())
            .spawn(move || pump(shared, &root, &sender))?;
    }

    if handles.is_empty() {
        anyhow::bail!(
            "none of the configured scan roots could be opened (Windows error {})",
            unsafe { GetLastError() }
        );
    }
    Ok(Directories {
        handles,
        receiver,
        roots: watched,
    })
}

fn open(root: &Path) -> Option<Handle> {
    let wide: Vec<u16> = std::ffi::OsStr::new(root)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Shares everything: this is an observer, and a watch that stopped anyone
    // from renaming a directory would be a lock, which is a different feature.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    (handle != INVALID_HANDLE_VALUE && !handle.is_null()).then_some(handle)
}

/// Reads notifications until the handle is closed.
fn pump(shared: Shared, root: &Path, sender: &mpsc::Sender<PathBuf>) {
    let mut buffer = vec![0u8; BUFFER];

    loop {
        let mut returned: u32 = 0;
        let ok = unsafe {
            ReadDirectoryChangesW(
                shared.0,
                buffer.as_mut_ptr() as *mut c_void,
                BUFFER as u32,
                1, // the whole subtree, which is the point
                FILTER,
                &mut returned,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        // Cancelled, closed, or the root went away. Either way there is nothing
        // left to watch here.
        if ok == 0 {
            return;
        }
        // Zero bytes means the buffer overflowed and the kernel discarded the
        // changes. Nothing can be recovered; the caller is told *something*
        // happened, which turns it into one full sweep.
        if returned == 0 {
            if sender.send(root.to_path_buf()).is_err() {
                return;
            }
            continue;
        }

        for name in parse(&buffer[..returned as usize]) {
            if sender.send(root.join(name)).is_err() {
                return;
            }
        }
    }
}

/// Walks the chain of `FILE_NOTIFY_INFORMATION` records in `buffer`.
fn parse(buffer: &[u8]) -> Vec<PathBuf> {
    let mut names = Vec::new();
    let mut offset = 0usize;

    loop {
        if offset + std::mem::size_of::<FileNotifyInformation>() > buffer.len() {
            break;
        }
        // Unaligned: the kernel packs these records back to back with only a
        // 4-byte guarantee, and `u32` fields inside want 4 while the struct as a
        // whole is read as one.
        let record = unsafe {
            std::ptr::read_unaligned(buffer.as_ptr().add(offset) as *const FileNotifyInformation)
        };

        let name_start = offset + std::mem::size_of::<FileNotifyInformation>();
        let name_end = name_start + record.file_name_length as usize;
        if name_end > buffer.len() {
            break;
        }
        // `FileNameLength` is a byte count of UTF-16 units, so it is always even
        // and the remainder is always empty.
        let (pairs, _) = buffer[name_start..name_end].as_chunks::<2>();
        let units: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).collect();
        names.push(PathBuf::from(String::from_utf16_lossy(&units)));

        if record.next_entry_offset == 0 {
            break;
        }
        offset += record.next_entry_offset as usize;
    }

    names
}
