//! Refusing *new* entries inside a protected directory.
//!
//! The handle locks cover every file that exists when the policy is applied and
//! stop the directory itself being renamed or removed, but creating a new entry
//! inside it opens no existing object, so no share mode is ever consulted.
//! Nothing about a handle can say "and nothing may be added here".
//!
//! A deny ACE can, and this is the one place Ralon uses one. Be exact about what
//! that buys, because the rest of this backend is deliberate about not relying
//! on permissions: the agent runs as the same user and *owns* these
//! directories, and an owner's `WRITE_DAC` is implicit. It cannot be denied —
//! tested, including with an explicit deny ACE on `WRITE_DAC` itself, which the
//! owner removed anyway. So an agent that decides to rewrite the ACL can create
//! files here again.
//!
//! That makes this a narrowing, not a guarantee. It refuses every ordinary
//! create — every editor, every `>` redirect, every agent's write tool, `copy`,
//! `move`, and renaming a file into place — and leaves only a route an agent
//! has to go out of its way to take. The handle locks are the part that cannot
//! be argued with; this is the part that closes the hole they cannot reach.
//! `security.md` says so in those words.
//!
//! Two rules keep it from being a footgun:
//!
//! - A directory whose ACL already names `Everyone` is left alone and reported.
//!   Ralon removes its ACE by rebuilding the list without it, and rebuilding
//!   someone else's `Everyone` entry out of existence would be a silent,
//!   permanent change to permissions it did not write.
//! - If Ralon is killed before it can undo this, the ACE stays behind. That
//!   fails *closed* — the leftover refuses writes to a directory the policy
//!   protects anyway — and `status` reports it, `ralon guard --stop` clears it.
//!
//! The ACL is assembled ACE by ACE rather than through `SetEntriesInAcl`.
//! That is not a preference: `SetEntriesInAcl` with `REVOKE_ACCESS` returned
//! `ERROR_SUCCESS` and left the ACE exactly where it was, so the undo silently
//! did nothing. Copying the entries by hand is longer and says what it does.

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// `SE_FILE_OBJECT` — the name is a filesystem path.
const SE_FILE_OBJECT: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;

/// Adding a file and adding a subdirectory. Deliberately not `FILE_DELETE_CHILD`:
/// existing children are already locked by handle, and denying it would leave
/// anything an agent did manage to create impossible to clean up.
const FILE_ADD_FILE: u32 = 0x0000_0002;
const FILE_ADD_SUBDIRECTORY: u32 = 0x0000_0004;
const NEW_ENTRIES: u32 = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY;

const ACL_REVISION: u32 = 2;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
/// `AclSizeInformation`
const ACL_SIZE_INFORMATION: u32 = 2;
/// Append, rather than insert at an index.
const MAXDWORD: u32 = 0xFFFF_FFFF;
const ERROR_SUCCESS: u32 = 0;

/// `S-1-1-0`, spelled out. A `SID` is a revision byte, a sub-authority count, a
/// 6-byte authority and then one `u32` per sub-authority — a fixed layout,
/// cheaper to write than to allocate through `AllocateAndInitializeSid` and
/// free again on every path.
#[repr(C, align(4))]
struct Sid([u8; 12]);
static EVERYONE: Sid = Sid([1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);

/// The fixed part of every ACE. What follows depends on the type; for the two
/// kinds that appear on a file it is an access mask and then a SID.
#[repr(C)]
struct AceHeader {
    ace_type: u8,
    ace_flags: u8,
    size: u16,
}

#[repr(C)]
#[derive(Default)]
struct AclSizeInformation {
    ace_count: u32,
    bytes_in_use: u32,
    bytes_free: u32,
}

#[link(name = "advapi32")]
extern "system" {
    fn GetNamedSecurityInfoW(
        object_name: *const u16,
        object_type: u32,
        security_information: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        security_descriptor: *mut *mut c_void,
    ) -> u32;

    fn SetNamedSecurityInfoW(
        object_name: *mut u16,
        object_type: u32,
        security_information: u32,
        owner: *mut c_void,
        group: *mut c_void,
        dacl: *mut c_void,
        sacl: *mut c_void,
    ) -> u32;

    fn GetAclInformation(
        acl: *mut c_void,
        information: *mut c_void,
        length: u32,
        class: u32,
    ) -> i32;
    fn InitializeAcl(acl: *mut c_void, length: u32, revision: u32) -> i32;
    fn GetAce(acl: *mut c_void, index: u32, ace: *mut *mut c_void) -> i32;
    fn AddAce(
        acl: *mut c_void,
        revision: u32,
        starting_index: u32,
        ace_list: *const c_void,
        ace_list_length: u32,
    ) -> i32;
    fn AddAccessDeniedAceEx(
        acl: *mut c_void,
        revision: u32,
        flags: u32,
        mask: u32,
        sid: *const c_void,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

/// Directories currently carrying Ralon's deny ACE. Dropping this takes it off
/// again; being killed before that leaves it on, which is the safe direction.
pub struct Narrowing {
    applied: Vec<Vec<u16>>,
}

impl Narrowing {
    pub fn directories(&self) -> usize {
        self.applied.len()
    }
}

impl Drop for Narrowing {
    fn drop(&mut self) {
        for path in &mut self.applied {
            // Nothing useful to do with a failure here: the process is on its
            // way out, and `status` reports a leftover ACE the next time.
            let _ = rewrite(path, Ace::Remove);
        }
    }
}

/// Refuses new entries in each of `directories`.
///
/// Returns the narrowing and anything the caller should say out loud. A
/// directory that cannot be narrowed is never fatal — the handle locks are the
/// guarantee and this only reaches further — but it is never silent either.
pub fn refuse_new_entries(directories: &[PathBuf]) -> (Narrowing, Vec<String>) {
    let mut applied = Vec::new();
    let mut warnings = Vec::new();

    for directory in directories {
        let mut wide = wide(directory);
        match rewrite(&mut wide, Ace::Add) {
            Ok(true) => applied.push(wide),
            Ok(false) => warnings.push(format!(
                "{} already grants or denies Everyone, so new files inside it are \
                 not refused — Ralon will not rewrite an ACL it did not write",
                directory.display()
            )),
            Err(code) => warnings.push(format!(
                "could not refuse new files inside {} (Windows error {code}); \
                 existing files there are still locked",
                directory.display()
            )),
        }
    }

    (Narrowing { applied }, warnings)
}

/// Directories still carrying the ACE from a run that did not get to clean up.
pub fn leftovers(directories: &[PathBuf]) -> Vec<PathBuf> {
    directories
        .iter()
        .filter(|directory| refuses_new_entries(directory))
        .cloned()
        .collect()
}

/// Takes the ACE off. Returns the directories it actually cleared.
pub fn clear(directories: &[PathBuf]) -> Vec<PathBuf> {
    let mut cleared = Vec::new();
    for directory in directories {
        if !refuses_new_entries(directory) {
            continue;
        }
        // Checked afterwards rather than trusted: the previous implementation
        // of this reported success and changed nothing.
        let _ = rewrite(&mut wide(directory), Ace::Remove);
        if !refuses_new_entries(directory) {
            cleared.push(directory.clone());
        }
    }
    cleared
}

enum Ace {
    Add,
    Remove,
}

/// Rebuilds the directory's DACL with Ralon's deny ACE added or taken out.
///
/// `Ok(false)` means the directory was deliberately left alone.
fn rewrite(wide: &mut [u16], change: Ace) -> Result<bool, u32> {
    let (descriptor, dacl) = read_dacl(wide)?;
    let result = build(wide, dacl, change);
    unsafe { LocalFree(descriptor) };
    result
}

fn build(wide: &mut [u16], dacl: *mut c_void, change: Ace) -> Result<bool, u32> {
    let existing = aces(dacl);

    // Ralon's own leftover does not count as somebody else's entry: a guard
    // that was killed rather than stopped should not lock the next run out of
    // the directory it was protecting.
    if matches!(change, Ace::Add)
        && existing
            .iter()
            .any(|ace| names_everyone(*ace) && !is_ours(*ace))
    {
        return Ok(false);
    }

    // The old entries, our own ACE, and room to spare. An ACL is capped at
    // 64 KB; anything approaching that was not written by a person.
    let size = bytes_in_use(dacl) + 64;
    let mut buffer = vec![0u32; (size as usize).div_ceil(4)];
    let acl = buffer.as_mut_ptr() as *mut c_void;

    if unsafe { InitializeAcl(acl, size, ACL_REVISION) } == 0 {
        return Err(last_error());
    }

    // Deny first, which is where the canonical order wants it: an allow entry
    // ahead of it would be evaluated first and grant what this is refusing.
    if matches!(change, Ace::Add)
        && unsafe {
            AddAccessDeniedAceEx(
                acl,
                ACL_REVISION,
                0, // applies to this directory, inherited by nothing inside it
                NEW_ENTRIES,
                std::ptr::addr_of!(EVERYONE) as *const c_void,
            )
        } == 0
    {
        return Err(last_error());
    }

    // Everything that was there, minus any of ours. Copied verbatim, so an
    // inherited entry stays flagged as inherited and keeps behaving like one.
    for ace in existing {
        if is_ours(ace) {
            continue;
        }
        let header = unsafe { &*(ace as *const AceHeader) };
        if unsafe { AddAce(acl, ACL_REVISION, MAXDWORD, ace, u32::from(header.size)) } == 0 {
            return Err(last_error());
        }
    }

    let code = unsafe {
        SetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null_mut(),
        )
    };
    if code == ERROR_SUCCESS {
        Ok(true)
    } else {
        Err(code)
    }
}

/// True when the directory carries the ACE Ralon writes.
fn refuses_new_entries(directory: &Path) -> bool {
    let Ok((descriptor, dacl)) = read_dacl(&wide(directory)) else {
        return false;
    };
    let refuses = aces(dacl).into_iter().any(is_ours);
    unsafe { LocalFree(descriptor) };
    refuses
}

/// Reads the directory's DACL, and the security descriptor that owns the memory
/// it lives in. The DACL points *into* the descriptor, so the caller frees the
/// descriptor, and not before it has finished with the DACL.
fn read_dacl(wide: &[u16]) -> Result<(*mut c_void, *mut c_void), u32> {
    let mut dacl: *mut c_void = std::ptr::null_mut();
    let mut descriptor: *mut c_void = std::ptr::null_mut();

    let code = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(code);
    }

    Ok((descriptor, dacl))
}

/// Pointers to each ACE in the DACL, in order.
///
/// A null DACL is not an empty one: it grants everybody everything and names
/// nobody, which is the one case where adding an entry is both safe and worth
/// doing, so it reads as no entries rather than as an error.
fn aces(dacl: *mut c_void) -> Vec<*mut c_void> {
    if dacl.is_null() {
        return Vec::new();
    }

    let mut found = Vec::new();
    for index in 0..count(dacl) {
        let mut ace: *mut c_void = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) } != 0 && !ace.is_null() {
            found.push(ace);
        }
    }
    found
}

fn size_information(dacl: *mut c_void) -> AclSizeInformation {
    let mut information = AclSizeInformation::default();
    if dacl.is_null() {
        return information;
    }
    unsafe {
        GetAclInformation(
            dacl,
            std::ptr::addr_of_mut!(information) as *mut c_void,
            std::mem::size_of::<AclSizeInformation>() as u32,
            ACL_SIZE_INFORMATION,
        )
    };
    information
}

fn count(dacl: *mut c_void) -> u32 {
    size_information(dacl).ace_count
}

fn bytes_in_use(dacl: *mut c_void) -> u32 {
    // The floor covers a null DACL, where the new ACL is built from nothing.
    size_information(dacl).bytes_in_use.max(64)
}

/// Whether this is the ACE Ralon writes: a deny, for Everyone, over exactly the
/// two rights that create things.
fn is_ours(ace: *mut c_void) -> bool {
    let header = unsafe { &*(ace as *const AceHeader) };
    if header.ace_type != ACCESS_DENIED_ACE_TYPE {
        return false;
    }
    mask(ace) == NEW_ENTRIES && names_everyone(ace)
}

/// The access mask of a deny or allow ACE, which follows the 4-byte header.
fn mask(ace: *mut c_void) -> u32 {
    unsafe { std::ptr::read_unaligned(ace.byte_add(4) as *const u32) }
}

/// Whether the ACE's trustee is `S-1-1-0`. The SID starts after the header and
/// the mask; comparing its bytes avoids resolving a name that is localised.
fn names_everyone(ace: *mut c_void) -> bool {
    let header = unsafe { &*(ace as *const AceHeader) };
    if usize::from(header.size) < 8 + EVERYONE.0.len() {
        return false;
    }
    let sid = unsafe { std::slice::from_raw_parts(ace.byte_add(8) as *const u8, EVERYONE.0.len()) };
    sid == EVERYONE.0
}

fn last_error() -> u32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32
}

fn wide(path: &Path) -> Vec<u16> {
    OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
