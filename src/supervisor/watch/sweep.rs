//! The watcher that watches nothing.
//!
//! Returned when a platform has no watcher, or has one that would not start.
//! It sleeps out the timeout and reports no changes, which is exactly the signal
//! the supervisor reads as "run a full sweep" — so the difference between having
//! a watcher and not having one is latency, and nothing else.
//!
//! It carries the reason it exists rather than being anonymous, because a
//! supervisor that has quietly degraded to once a minute looks identical to one
//! that has not until somebody wonders why a new repository took so long.

use std::path::PathBuf;
use std::time::Duration;

use super::Watcher;

pub struct Blind {
    reason: String,
}

impl Blind {
    pub fn new(reason: String) -> Blind {
        Blind { reason }
    }
}

impl Watcher for Blind {
    fn changes(&mut self, timeout: Duration) -> Vec<PathBuf> {
        std::thread::sleep(timeout);
        Vec::new()
    }

    fn describe(&self) -> String {
        self.reason.clone()
    }
}
