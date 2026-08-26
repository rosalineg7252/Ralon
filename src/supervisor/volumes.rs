//! Which drives this machine has, so `install` can say what it is *not*
//! covering.
//!
//! Reporting only. Nothing here is ever swept, watched or added as a scope —
//! that would be exactly the guess this module exists to avoid making. The
//! problem being solved is narrower and entirely a Windows one: the first-run
//! default scope is the home directory, the home directory is on `C:`, and a
//! great many developers keep their repositories on `D:` or `E:`. Those people
//! would otherwise write an `agent.lock`, see nothing happen, and have no reason
//! to suspect the scope model exists.
//!
//! So `install` enumerates the fixed drives, subtracts the ones already covered,
//! and prints the exact `ralon scope add` for the rest. Detected and named, never
//! assumed — the developer still decides.
//!
//! Unix has no equivalent question. There is one tree, and a home directory is
//! inside it.

use std::path::PathBuf;

/// Drive roots holding local storage: `C:\`, `D:\`.
///
/// Removable and network drives are left out on purpose. A scope on a USB stick
/// or a mapped share is a scope that disappears, and suggesting one would be
/// suggesting a supervisor that reports a directory it cannot reach.
#[cfg(windows)]
pub fn fixed_roots() -> Vec<PathBuf> {
    /// `DRIVE_FIXED`
    const FIXED: u32 = 3;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetLogicalDrives() -> u32;
        fn GetDriveTypeW(root: *const u16) -> u32;
    }

    // Safety: takes no arguments and cannot fail; 0 means "could not tell",
    // which falls out of the loop below as an empty list.
    let mask = unsafe { GetLogicalDrives() };
    let mut found = Vec::new();

    for letter in 0..26u32 {
        if mask & (1 << letter) == 0 {
            continue;
        }
        let letter = char::from(b'A' + letter as u8);
        let root = format!("{letter}:\\");
        let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();

        // Safety: `wide` is NUL-terminated and outlives the call.
        if unsafe { GetDriveTypeW(wide.as_ptr()) } == FIXED {
            found.push(PathBuf::from(root));
        }
    }

    found
}

#[cfg(not(windows))]
pub fn fixed_roots() -> Vec<PathBuf> {
    Vec::new()
}
