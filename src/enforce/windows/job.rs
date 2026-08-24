//! Tying the command's life to Ralon's.
//!
//! The locks live in this process, so they end when it does. That is normally
//! the point — nothing to clean up — but it leaves one hole: the agent runs as
//! the same user and can terminate its parent, and the moment Ralon dies the
//! files are writable while the agent is still running.
//!
//! A job object with `KILL_ON_JOB_CLOSE` closes it. The command is assigned to
//! a job whose only handle belongs to Ralon; when that handle goes — cleanly,
//! by `taskkill`, or by a crash — the kernel terminates everything in the job.
//! So the agent can end its own supervision, but it cannot outlive it, and
//! there is no window in which the protection is gone and the agent is not.

use std::os::windows::io::{AsRawHandle, RawHandle};
use std::process::Child;

type Handle = *mut core::ffi::c_void;

const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;

#[repr(C)]
#[derive(Default)]
struct BasicLimits {
    per_process_user_time_limit: i64,
    per_job_user_time_limit: i64,
    limit_flags: u32,
    minimum_working_set_size: usize,
    maximum_working_set_size: usize,
    active_process_limit: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
}

#[repr(C)]
#[derive(Default)]
struct IoCounters {
    read_operation_count: u64,
    write_operation_count: u64,
    other_operation_count: u64,
    read_transfer_count: u64,
    write_transfer_count: u64,
    other_transfer_count: u64,
}

#[repr(C)]
#[derive(Default)]
struct ExtendedLimits {
    basic: BasicLimits,
    io: IoCounters,
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory_used: usize,
    peak_job_memory_used: usize,
}

extern "system" {
    fn CreateJobObjectW(attributes: *mut core::ffi::c_void, name: *const u16) -> Handle;
    fn SetInformationJobObject(
        job: Handle,
        class: i32,
        information: *const core::ffi::c_void,
        length: u32,
    ) -> i32;
    fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
}

/// Owns the job. Dropping it kills whatever is still inside.
pub struct Leash(Handle);

impl Drop for Leash {
    fn drop(&mut self) {
        // Closing the last handle is what triggers the kill.
        unsafe { CloseHandle(self.0) };
    }
}

/// Puts `child` in a job that dies with this process.
///
/// Returns `None` when the job cannot be created or assigned — an older
/// container image, or a child already inside a job that forbids nesting. The
/// locks still hold for as long as Ralon lives; only the kill-the-parent
/// scenario is left open, and `run` says so rather than pretending.
pub fn tie_to_this_process(child: &Child) -> Option<Leash> {
    unsafe {
        let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
        if job.is_null() {
            return None;
        }

        let mut limits = ExtendedLimits::default();
        limits.basic.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        let set = SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            &limits as *const ExtendedLimits as *const core::ffi::c_void,
            std::mem::size_of::<ExtendedLimits>() as u32,
        );
        let assigned = AssignProcessToJobObject(job, child.as_raw_handle() as RawHandle as Handle);

        if set == 0 || assigned == 0 {
            CloseHandle(job);
            return None;
        }

        Some(Leash(job))
    }
}
