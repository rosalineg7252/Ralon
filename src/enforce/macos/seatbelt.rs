//! Applying a Seatbelt profile to this process.
//!
//! One call, and the shape of `run` everywhere else follows from it: the
//! profile applies to the *calling* process and is inherited across `exec` and
//! by every descendant, with no way to leave it. So Ralon restricts itself and
//! then becomes the command, exactly as on Linux — no supervisor, nothing to
//! kill, and no way for the agent to shell out of it.
//!
//! `sandbox_init` has been deprecated since 10.8 and has no public header. It
//! is also what Chromium, Firefox and every other sandboxed thing on macOS
//! actually uses, and the supported alternative — the App Sandbox — is an
//! entitlement on a signed `.app` bundle, which a command-line tool cannot be.
//! The choice is this or nothing, so `security.md` names it as a dependency
//! rather than leaving it implied.

use std::ffi::{c_char, CString};

extern "C" {
    /// `int sandbox_init(const char *profile, uint64_t flags, char **errorbuf)`
    ///
    /// With `flags = 0` the first argument is a profile in SBPL, rather than
    /// the name of a built-in one.
    fn sandbox_init(profile: *const c_char, flags: u64, error: *mut *mut c_char) -> i32;
    fn sandbox_free_error(error: *mut c_char);
    fn strlen(text: *const c_char) -> usize;
}

/// The profile is text, not a name.
const PROFILE_IS_LITERAL: u64 = 0;

/// Applies `profile` to this process. Once this returns `Ok`, it cannot be
/// undone by this process or any of its children.
pub fn apply(profile: &str) -> anyhow::Result<()> {
    // An interior NUL would truncate the profile, and a truncated profile is a
    // profile that denies less than it says it does.
    let text = CString::new(profile)
        .map_err(|_| anyhow::anyhow!("the sandbox profile contains a NUL byte"))?;

    let mut error: *mut c_char = std::ptr::null_mut();
    let code = unsafe { sandbox_init(text.as_ptr(), PROFILE_IS_LITERAL, &mut error) };

    if code == 0 {
        // The buffer is only written on failure, but freeing a non-null one
        // here costs nothing and leaks nothing if that ever changes.
        if !error.is_null() {
            unsafe { sandbox_free_error(error) };
        }
        return Ok(());
    }

    let detail = read_error(error);
    anyhow::bail!(
        "the kernel refused the sandbox profile: {detail}. Nothing was applied, \
         so the command was not started."
    )
}

/// Copies the kernel's error string out and frees the buffer it came in.
fn read_error(error: *mut c_char) -> String {
    if error.is_null() {
        return "no reason given".to_string();
    }

    let length = unsafe { strlen(error) };
    let bytes = unsafe { std::slice::from_raw_parts(error as *const u8, length) };
    let detail = String::from_utf8_lossy(bytes).into_owned();
    unsafe { sandbox_free_error(error) };
    detail
}

/// Whether this process can be sandboxed at all.
///
/// Always, and the reason it cannot be probed is worth stating: applying a
/// profile is one-way, so a probe that tried it would restrict the process
/// doing the probing. `sandbox_init` is in libSystem, which is linked into
/// everything, so if it were missing this binary would not have started.
///
/// That makes `status` a statement about the platform rather than about this
/// machine — and it is why `apply` reports the kernel's own refusal verbatim
/// instead of assuming a profile that compiled here will be accepted there.
pub fn available() -> bool {
    true
}
