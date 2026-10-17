use super::*;

impl OmikronConnection {
    pub(super) async fn read_loop(self: Arc<Self>, connection: Arc<MTPConnection>) {
        let attempt = self
            .bound_attempt
            .as_ref()
            .expect("read loop is attempt-scoped");
        let mut handlers = JoinSet::new();
        loop {
            {
                let mut preparation = self.preparation_tasks.lock().await;
                while let Some(result) = preparation.try_join_next() {
                    if let Err(error) = result {
                        self.worker_failure("preparation", Some(attempt.generation), &error);
                    }
                }
            }
            let result = tokio::select! {
                _ = attempt.cancellation.cancelled() => break,
                completed = handlers.join_next(), if !handlers.is_empty() => {
                    if let Some(Err(error)) = completed {
                        self.worker_failure("handler", Some(attempt.generation), &error);
                    }
                    continue;
                }
                result = connection.receive() => result,
            };
            match result {
                Ok(cv) => {
                    if !cv.is_type(CommunicationType::Relay)
                        && cv
                            .id()
                            .is_some_and(|id| attempt.responses.complete(id, cv.clone()))
                    {
                        continue;
                    }
                    let permit = tokio::select! {
                        _ = attempt.cancellation.cancelled() => break,
                        permit = self.handler_semaphore.clone().acquire_owned() => permit,
                    };
                    if attempt.cancellation.is_cancelled() {
                        break;
                    }
                    let self_clone = self.clone();
                    let pending = self.track_operation();
                    handlers.spawn(async move {
                        let _pending = pending;
                        let _permit = permit;
                        self_clone.handle_message(cv).await;
                    });
                }
                Err(e) => {
                    log!("Omikron attempt {} receive failed: {e}", attempt.generation);
                    break;
                }
            }
            if !connection.receiver.is_open() {
                break;
            }
        }
        self.lifecycle_event(
            LogLevel::Info,
            "connector.reader.terminated",
            Some(attempt.generation),
            format_args!(""),
        );
        attempt.close();
        attempt.sender.close().await;
        // These handlers can commit durable account mutations. Do not abort
        // them at an arbitrary await; responses remain pinned to this attempt.
        while let Some(result) = handlers.join_next().await {
            if let Err(error) = result {
                self.worker_failure("handler", Some(attempt.generation), &error);
            }
        }
        let mut preparation = self.preparation_tasks.lock().await;
        while let Some(result) = preparation.join_next().await {
            if let Err(error) = result {
                self.worker_failure("preparation", Some(attempt.generation), &error);
            }
        }
        self.lifecycle_event(
            LogLevel::Info,
            "connector.handlers.drained",
            Some(attempt.generation),
            format_args!(""),
        );
    }

    pub(super) async fn maintenance_loop(self: Arc<Self>, connection: Arc<MTPConnection>) {
        let attempt = self
            .bound_attempt
            .as_ref()
            .expect("attempt-scoped maintenance");
        loop {
            tokio::select! {
                _ = attempt.cancellation.cancelled() => break,
                _ = sleep(MAINTENANCE_INTERVAL) => {},
            }

            if !self.state.read().await.is_connected() {
                break;
            }

            if self.bound_attempt.as_ref().is_none_or(|attempt| {
                attempt.cancellation.is_cancelled() || !attempt.sender.is_open()
            }) {
                break;
            }

            if let Some(ping) = connection.get_ping() {
                let ping_ms = i64::try_from(ping.as_millis()).unwrap_or(i64::MAX);
                *self.last_ping.lock().await = ping_ms;
                self.app.lock().unwrap().push_ping_val(ping_ms as f64);
            }

            // Client queue records remain durable if delivery is interrupted.
            tokio::select! {
                _ = attempt.cancellation.cancelled() => break,
                _ = self.flush_pending_relays() => {},
            }
            if let Err(error) = relay_replay::prune_completed(
                now_millis_i64().saturating_sub(relay_replay::RELAY_RETENTION_MILLIS),
            ) {
                log!("Relay replay cleanup failed: {}", error);
            }
            self.password_auth.prune();
            if let Err(error) = iota_storage::util::protected_replay::prune(
                now_millis_i64().saturating_sub(7 * 24 * 60 * 60 * 1000),
            ) {
                log!("Password command replay cleanup failed: {error}");
            }
        }
    }

    pub(super) async fn invitation_loop(self: Arc<Self>) {
        let attempt = self
            .bound_attempt
            .as_ref()
            .expect("attempt-scoped invitations");
        loop {
            // Cancellation only drops external requests and replies. Invitation
            // mutations are synchronous and pending actions remain in SQLite.
            tokio::select! {
                biased;
                _ = attempt.cancellation.cancelled() => break,
                _ = async {
                    if let Err(error) = self.sync_omega_invitations().await {
                        log!("Omega invitation synchronization failed: {error}");
                    }
                    self.flush_pending_invitation_actions().await;
                } => {},
            }
            tokio::select! {
                _ = attempt.cancellation.cancelled() => break,
                _ = sleep(MAINTENANCE_INTERVAL) => {},
            }
        }
    }
}
