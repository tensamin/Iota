use super::*;
use iota_logger::{LogLevel, PrintType, log_event};

impl OmikronConnection {
    pub(super) fn lifecycle_event(
        &self,
        level: LogLevel,
        event: &'static str,
        generation: Option<u64>,
        details: std::fmt::Arguments<'_>,
    ) {
        log_event!(
            PrintType::Omikron,
            level,
            event,
            "connector={} attempt={} pending_operations={} {details}",
            self.connection_id,
            generation.map_or_else(|| "none".into(), |value| value.to_string()),
            self.pending_operations.load(Ordering::Acquire),
        );
    }

    pub(super) fn worker_failure(
        &self,
        worker: &'static str,
        generation: Option<u64>,
        error: &tokio::task::JoinError,
    ) {
        self.worker_failed.store(true, Ordering::Release);
        // Panic payloads can contain protocol data. Record task metadata only.
        self.lifecycle_event(
            LogLevel::Error,
            "connector.worker.failed",
            generation,
            format_args!(
                "worker={worker} task={} panic={} cancelled={}",
                error.id(),
                error.is_panic(),
                error.is_cancelled(),
            ),
        );
    }
}
