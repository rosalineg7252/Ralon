//! FSEvents, one stream covering every scan root.
//!
//! The right primitive for this on macOS and the only one that scales: FSEvents
//! watches whole subtrees from a single registration, where `kqueue` needs a
//! file descriptor per directory and reports nothing about a subtree at all.
//!
//! ## Why the stream starts at `SinceNow`
//!
//! FSEvents can replay history — hand it the last event id you saw and it tells
//! you what happened while you were not running, which reads like the exact
//! answer to "what changed across a reboot". It is not worth it here. Using it
//! correctly means persisting an event id *and* the volume's UUID, noticing when
//! the volume changed, and handling the flag that says the history was dropped
//! anyway — at the end of which the fallback is a full sweep. The supervisor
//! already does a full sweep on startup, unconditionally, which answers the same
//! question with no state to keep and no way to be subtly wrong about it.
//!
//! ## Verification
//!
//! Nobody working on this repository can run it; there is no container for
//! macOS. That is exactly why the sweep in `watch/mod.rs` is described as the
//! correctness boundary rather than a nicety — a mistake in the FFI below
//! degrades the supervisor to noticing a repository within a minute, not to
//! missing it. The parts that can be checked anywhere are, in `supervisor/mod.rs`.

use std::ffi::{c_char, c_void, CStr};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

use anyhow::Result;

use super::Watcher;

type CFRef = *const c_void;
type StreamRef = *mut c_void;

const UTF8: u32 = 0x0800_0100;
const SINCE_NOW: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// Report as soon as something happens rather than waiting out the latency
/// window first, and report file paths rather than the enclosing directory.
const NO_DEFER: u32 = 0x0000_0002;
const FILE_EVENTS: u32 = 0x0000_0010;

/// Seconds of coalescing. Long enough that a `git checkout` is a handful of
/// callbacks instead of thousands; short enough that creating `agent.lock` by
/// hand feels immediate.
const LATENCY: f64 = 0.3;

#[repr(C)]
struct StreamContext {
    version: isize,
    info: *mut c_void,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
}

type Callback = unsafe extern "C" fn(
    stream: StreamRef,
    info: *mut c_void,
    count: usize,
    paths: *mut c_void,
    flags: *const u32,
    ids: *const u64,
);

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFStringCreateWithBytes(
        allocator: CFRef,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        external: u8,
    ) -> CFRef;
    fn CFArrayCreate(
        allocator: CFRef,
        values: *const CFRef,
        count: isize,
        callbacks: *const c_void,
    ) -> CFRef;
    fn CFRelease(reference: CFRef);
    fn CFRunLoopGetCurrent() -> CFRef;
    fn CFRunLoopRun();
    fn CFRunLoopStop(run_loop: CFRef);

    static kCFTypeArrayCallBacks: c_void;
    static kCFRunLoopDefaultMode: CFRef;
}

#[link(name = "CoreServices", kind = "framework")]
extern "C" {
    fn FSEventStreamCreate(
        allocator: CFRef,
        callback: Callback,
        context: *const StreamContext,
        paths: CFRef,
        since: u64,
        latency: f64,
        flags: u32,
    ) -> StreamRef;
    fn FSEventStreamScheduleWithRunLoop(stream: StreamRef, run_loop: CFRef, mode: CFRef);
    fn FSEventStreamStart(stream: StreamRef) -> u8;
    fn FSEventStreamStop(stream: StreamRef);
    fn FSEventStreamInvalidate(stream: StreamRef);
    fn FSEventStreamRelease(stream: StreamRef);
}

/// A `CFRunLoopRef` that may cross a thread boundary.
///
/// Safety: `CFRunLoopStop` is documented as safe to call from any thread; it is
/// how a run loop is meant to be ended from outside.
struct Stoppable(CFRef);
unsafe impl Send for Stoppable {}

pub struct Events {
    receiver: Receiver<PathBuf>,
    run_loop: Option<Stoppable>,
    roots: Vec<PathBuf>,
}

impl Drop for Events {
    fn drop(&mut self) {
        if let Some(run_loop) = self.run_loop.take() {
            unsafe { CFRunLoopStop(run_loop.0) };
        }
    }
}

impl Watcher for Events {
    fn changes(&mut self, timeout: Duration) -> Vec<PathBuf> {
        let mut changed = Vec::new();
        match self.receiver.recv_timeout(timeout) {
            Ok(path) => changed.push(path),
            Err(RecvTimeoutError::Timeout) => return changed,
            Err(RecvTimeoutError::Disconnected) => {
                std::thread::sleep(timeout);
                return changed;
            }
        }
        while let Ok(path) = self.receiver.try_recv() {
            changed.push(path);
        }
        changed
    }

    fn describe(&self) -> String {
        format!(
            "enforcement starts on a new policy in {} (FSEvents)",
            self.roots
                .iter()
                .map(|root| crate::supervisor::registry::display(root))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// Handed to the callback as its `info` pointer, and owned by the watcher
/// thread so it is dropped when the run loop ends and not before.
struct Sink {
    sender: Sender<PathBuf>,
}

unsafe extern "C" fn on_events(
    _stream: StreamRef,
    info: *mut c_void,
    count: usize,
    paths: *mut c_void,
    _flags: *const u32,
    _ids: *const u64,
) {
    if info.is_null() || paths.is_null() {
        return;
    }
    // Safety: `info` is the `Sink` given to `FSEventStreamCreate`, which the
    // watcher thread keeps alive for as long as the stream is scheduled.
    let sink = unsafe { &*(info as *const Sink) };
    // Without `kFSEventStreamCreateFlagUseCFTypes` this is a plain `char **`.
    let paths = paths as *const *const c_char;

    for index in 0..count {
        let entry = unsafe { *paths.add(index) };
        if entry.is_null() {
            continue;
        }
        let bytes = unsafe { CStr::from_ptr(entry) }.to_bytes();
        let _ = sink
            .sender
            .send(PathBuf::from(String::from_utf8_lossy(bytes).into_owned()));
    }
}

pub fn start(roots: &[PathBuf]) -> Result<Events> {
    let (sender, receiver) = mpsc::channel();
    let (ready, started) = mpsc::channel();
    let watched: Vec<PathBuf> = roots.to_vec();
    let paths: Vec<String> = roots
        .iter()
        .map(|root| root.to_string_lossy().into_owned())
        .collect();

    // The stream has to be created, scheduled and run on one thread, because
    // the run loop it is scheduled on is that thread's. The thread reports back
    // whether it got that far, so `start` fails here rather than returning a
    // watcher that will never say anything.
    std::thread::Builder::new()
        .name("ralon-watch".to_string())
        .spawn(move || pump(&paths, sender, &ready))?;

    match started.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(run_loop)) => Ok(Events {
            receiver,
            run_loop: Some(run_loop),
            roots: watched,
        }),
        Ok(Err(reason)) => anyhow::bail!("{reason}"),
        Err(_) => anyhow::bail!("the FSEvents thread did not start within five seconds"),
    }
}

/// Creates the stream and runs the loop it is scheduled on. Returns when
/// `CFRunLoopStop` is called from `Drop`.
fn pump(paths: &[String], sender: Sender<PathBuf>, ready: &Sender<Result<Stoppable, String>>) {
    let mut strings: Vec<CFRef> = Vec::with_capacity(paths.len());
    for path in paths {
        let string = unsafe {
            CFStringCreateWithBytes(
                std::ptr::null(),
                path.as_ptr(),
                path.len() as isize,
                UTF8,
                0,
            )
        };
        if string.is_null() {
            for string in &strings {
                unsafe { CFRelease(*string) };
            }
            let _ = ready.send(Err(format!("could not represent {path} as a CFString")));
            return;
        }
        strings.push(string);
    }

    let array = unsafe {
        CFArrayCreate(
            std::ptr::null(),
            strings.as_ptr(),
            strings.len() as isize,
            std::ptr::addr_of!(kCFTypeArrayCallBacks),
        )
    };
    // The array retains each string; this side is done with them either way.
    for string in &strings {
        unsafe { CFRelease(*string) };
    }
    if array.is_null() {
        let _ = ready.send(Err("could not build the list of paths to watch".to_string()));
        return;
    }

    // Outlives the stream: the callback dereferences this pointer, so it must
    // not move or drop while the stream is scheduled. It is dropped at the end
    // of this function, after the stream has been invalidated.
    let sink = Box::new(Sink { sender });
    let context = StreamContext {
        version: 0,
        info: std::ptr::addr_of!(*sink) as *mut c_void,
        retain: std::ptr::null(),
        release: std::ptr::null(),
        copy_description: std::ptr::null(),
    };

    let stream = unsafe {
        FSEventStreamCreate(
            std::ptr::null(),
            on_events,
            &context,
            array,
            SINCE_NOW,
            LATENCY,
            NO_DEFER | FILE_EVENTS,
        )
    };
    unsafe { CFRelease(array) };
    if stream.is_null() {
        let _ = ready.send(Err("FSEventStreamCreate returned nothing".to_string()));
        return;
    }

    let run_loop = unsafe { CFRunLoopGetCurrent() };
    unsafe {
        FSEventStreamScheduleWithRunLoop(stream, run_loop, kCFRunLoopDefaultMode);
    }
    if unsafe { FSEventStreamStart(stream) } == 0 {
        unsafe {
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
        }
        let _ = ready.send(Err(
            "FSEventStreamStart refused to start the stream".to_string()
        ));
        return;
    }

    if ready.send(Ok(Stoppable(run_loop))).is_err() {
        // Nobody is waiting for this any more, so there is nothing to watch for.
        unsafe {
            FSEventStreamStop(stream);
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
        }
        return;
    }

    unsafe { CFRunLoopRun() };

    unsafe {
        FSEventStreamStop(stream);
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
    }
    drop(sink);
}
