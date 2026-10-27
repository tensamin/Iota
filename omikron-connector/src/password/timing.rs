use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

#[derive(Clone, Copy)]
pub(super) enum Stage {
    Authority,
    Account,
    Ke1,
    Ke3,
    ProtectedResponse,
}

const NAMES: [&str; 5] = [
    "authority_lookup",
    "account_lookup",
    "opaque_ke1",
    "opaque_ke3",
    "protected_response",
];
static COUNTS: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
static FAILURES: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
static MILLIS: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

/// Fixed stage labels only. Drop also records timeout/cancellation failures.
pub(super) struct Timing {
    stage: Stage,
    started: Instant,
    success: bool,
}
impl Timing {
    pub(super) fn start(stage: Stage) -> Self {
        Self {
            stage,
            started: Instant::now(),
            success: false,
        }
    }
    pub(super) fn success(&mut self) {
        self.success = true;
    }
}
impl Drop for Timing {
    fn drop(&mut self) {
        let index = self.stage as usize;
        let elapsed = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        COUNTS[index].fetch_add(1, Ordering::Relaxed);
        MILLIS[index].fetch_add(elapsed, Ordering::Relaxed);
        if !self.success {
            FAILURES[index].fetch_add(1, Ordering::Relaxed);
        }
        iota_logger::log!(
            "Password stage: stage={} elapsed_ms={} success={}",
            NAMES[index],
            elapsed,
            self.success
        );
    }
}

pub fn snapshot() -> Vec<(&'static str, u64, u64, u64)> {
    NAMES
        .iter()
        .enumerate()
        .map(|(index, name)| {
            (
                *name,
                COUNTS[index].load(Ordering::Relaxed),
                FAILURES[index].load(Ordering::Relaxed),
                MILLIS[index].load(Ordering::Relaxed),
            )
        })
        .collect()
}
