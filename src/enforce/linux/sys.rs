//! Thin wrappers over the syscalls both Linux backends need.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use anyhow::{Context, Result};

pub fn cstring(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("path contains a null byte: {}", path.display()))
}

pub fn check(result: libc::c_int) -> io::Result<()> {
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
pub fn probe(action: impl Fn() -> io::Result<()>) -> io::Result<()> {
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
