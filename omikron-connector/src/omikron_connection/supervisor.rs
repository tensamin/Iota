use super::*;

impl OmikronConnection {
    pub async fn connect(self: &Arc<Self>) {
        if self.connection_loop_handle.lock().await.is_none() {
            self.clone().start().await;
        }
    }

    pub async fn start(self: Arc<Self>) {
        let mut supervisor = self.connection_loop_handle.lock().await;
        if supervisor.is_some() || self.cancellation.is_cancelled() {
            return;
        }

        if self.shutdown_tx.lock().await.is_none() {
            let (shutdown_tx, _) = watch::channel(false);
            *self.shutdown_tx.lock().await = Some(shutdown_tx);
        }
        self.shutdown_tx
            .lock()
            .await
            .as_ref()
            .unwrap()
            .send_replace(false);

        *self.reconnect_on_close.write().await = true;

        self.lifecycle_event(
            LogLevel::Info,
            "connector.supervisor.started",
            None,
            format_args!(""),
        );

        let self_clone = self.clone();
        let handle = tokio::spawn(async move {
            self_clone.connection_loop().await;
        });

        *supervisor = Some(handle);
    }

    pub async fn stop(&self) -> Result<ShutdownOutcome, ConnectorShutdownError> {
        self.stop_with_timeout(Duration::from_secs(5)).await
    }

    pub(super) async fn stop_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<ShutdownOutcome, ConnectorShutdownError> {
        self.drain(timeout, true).await
    }

    pub(super) async fn drain(
        &self,
        timeout: Duration,
        terminal: bool,
    ) -> Result<ShutdownOutcome, ConnectorShutdownError> {
        let deadline = tokio::time::Instant::now() + timeout;
        self.lifecycle_event(
            LogLevel::Info,
            "connector.drain.started",
            None,
            format_args!("terminal={terminal} budget_ms={}", timeout.as_millis()),
        );
        *self.reconnect_on_close.write().await = false;
        if terminal {
            self.cancellation.cancel();
        }
        if let Some(tx) = self.shutdown_tx.lock().await.as_ref() {
            tx.send_replace(true);
        }
        let attempt = self.active_attempt.write().await.take();
        if let Some(attempt) = attempt {
            attempt.close();
            self.lifecycle_event(
                LogLevel::Info,
                "connector.transport.closed",
                Some(attempt.generation),
                format_args!("reason=drain"),
            );
        }
        let mut supervisor =
            match tokio::time::timeout_at(deadline, self.connection_loop_handle.lock()).await {
                Ok(supervisor) => supervisor,
                Err(_) => {
                    return Ok(self.incomplete_drain("supervisor_lock"));
                }
            };
        if supervisor.is_none() && !self.preparation_tasks.lock().await.is_empty() {
            let preparation = self.preparation_tasks.clone();
            let owner = self.clone();
            *supervisor = Some(tokio::spawn(async move {
                let mut tasks = preparation.lock().await;
                while let Some(result) = tasks.join_next().await {
                    if let Err(error) = result {
                        owner.worker_failure("preparation", None, &error);
                    }
                }
            }));
        }
        if let Some(handle) = supervisor.as_mut() {
            match tokio::time::timeout_at(deadline, handle).await {
                Ok(result) => {
                    *supervisor = None;
                    if let Err(error) = &result {
                        self.worker_failure("supervisor", None, error);
                    }
                    result?;
                }
                Err(_) => {
                    return Ok(self.incomplete_drain("supervisor_join"));
                }
            }
        }
        self.set_state(ConnectionState::Disconnected).await;
        if self.worker_failed.load(Ordering::Acquire) {
            self.lifecycle_event(
                LogLevel::Error,
                "connector.drain.failed",
                None,
                format_args!("reason=unresolved_worker"),
            );
            return Err(ConnectorShutdownError::UnresolvedWorker);
        }
        self.lifecycle_event(
            LogLevel::Info,
            "connector.drain.complete",
            None,
            format_args!(""),
        );
        Ok(ShutdownOutcome::Complete)
    }

    fn incomplete_drain(&self, phase: &'static str) -> ShutdownOutcome {
        let pending_operations = self.pending_operations.load(Ordering::Acquire).max(1);
        self.lifecycle_event(
            LogLevel::Warn,
            "connector.drain.incomplete",
            None,
            format_args!(
                "phase={phase} remaining_work={pending_operations} process_workers=retained"
            ),
        );
        ShutdownOutcome::Incomplete { pending_operations }
    }

    pub(super) async fn connection_loop(self: Arc<Self>) {
        let mut reconnect_delay = RECONNECT_DELAY;
        let shutdown_rx = self.shutdown_tx.lock().await.as_ref().unwrap().subscribe();
        let mut shutdown_rx = shutdown_rx;

        loop {
            {
                let mut drains = self.draining_attempts.lock().await;
                while let Some(result) = drains.try_join_next() {
                    if let Err(error) = result {
                        self.worker_failure("attempt_drain", None, &error);
                    }
                }
            }
            if *shutdown_rx.borrow() || self.cancellation.is_cancelled() {
                log_t!("omikron_connection_loop_shutdown");
                break;
            }

            if !*self.reconnect_on_close.read().await {
                break;
            }

            let retry_reason = match self.clone().connect_once().await {
                Ok(result) => {
                    if result.became_healthy {
                        reconnect_delay = RECONNECT_DELAY;
                    }
                    if !*self.reconnect_on_close.read().await {
                        break;
                    }
                    "Connection lost".to_string()
                }
                Err(e) => {
                    if self.auth_failure.read().await.is_some() {
                        log!("Authentication failed, stopping reconnection: {}", e);
                        break;
                    }
                    format!("Connection failed: {e}")
                }
            };

            let delay = jittered_reconnect_delay(reconnect_delay);
            self.lifecycle_event(
                LogLevel::Warn,
                "connector.reconnect.scheduled",
                None,
                format_args!("delay_ms={} reason={retry_reason:?}", delay.as_millis()),
            );
            tokio::select! {
                _ = sleep(delay) => {}
                _ = self.cancellation.cancelled() => break,
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }

            reconnect_delay = std::cmp::min(reconnect_delay * 2, MAX_RECONNECT_DELAY);
        }
        self.lifecycle_event(
            LogLevel::Info,
            "connector.reconnect.stopped",
            None,
            format_args!(""),
        );
        self.join_draining_attempts().await;
    }

    pub(super) async fn join_draining_attempts(&self) {
        let mut drains = self.draining_attempts.lock().await;
        while let Some(result) = drains.join_next().await {
            if let Err(error) = result {
                self.worker_failure("attempt_drain", None, &error);
            }
        }
    }
}

impl OmikronConnection {
    pub(super) async fn connect_once(self: Arc<Self>) -> Result<ConnectionAttemptResult, String> {
        let mut shutdown = self.shutdown_tx.lock().await.as_ref().unwrap().subscribe();
        if *shutdown.borrow() || self.cancellation.is_cancelled() {
            return Ok(ConnectionAttemptResult {
                became_healthy: false,
            });
        }
        self.set_state(ConnectionState::Connecting).await;
        log_t!("omikron_connecting");

        // Discovery and authentication are disposable preparation. No child
        // workers or published attempt exist until this future completes.
        let preparation = async {
            let identity = self
                .load_or_migrate_keyring()
                .await
                .map_err(|error| format!("Iota identity initialization failed: {error}"))?;
            let keyring = identity.keyring();
            *self.keyring.write().await = Some(keyring.clone());
            self.initialize_password_auth(identity_path());

            let existing_iota_id = CONFIG.load().iota_id;

            let endpoint = self.resolve_omikron_endpoint(existing_iota_id).await?;

            let addr_str = format!("https://{}:{}", endpoint.host, endpoint.port);

            log!("Connecting to Omikron at {}", addr_str);

            let policy = Policy::default()
                .with_send_mode(SendMode::PersistentStream)
                .with_timeouts(
                    Duration::from_millis(2_000),
                    Duration::from_millis(2_000),
                    Duration::from_millis(30_000),
                )
                .with_keep_alive(Some(Duration::from_secs(6)))
                .with_receiver_queue_capacity(1000)
                .with_max_concurrent_stream_tasks(10)
                .with_persistent_stream_retries(5, Duration::from_secs(5));
            let client_config = ClientConfig::new(&addr_str)
                .with_description("iota")
                .with_policy(policy)
                .with_ping_interval(MAINTENANCE_INTERVAL);

            let connection = match Client::auth_connect_or_register(
                client_config,
                existing_iota_id,
                &keyring,
                &endpoint.public_key,
            )
            .await
            {
                Ok(connection) => connection,
                Err(mtp::common::CommunicationError::AuthenticationFailed(reason)) => {
                    /* MTP currently combines invalid proofs with timeouts and backend
                     * failures in this variant. Retrying is safe; stopping here can
                     * strand an Iota during a temporary Omega outage. */
                    return Err(format!("Authentication attempt failed: {reason}"));
                }
                Err(e) => return Err(format!("Connection failed: {}", e)),
            };

            Ok::<_, String>((connection, endpoint, existing_iota_id))
        };
        let (connection, endpoint, existing_iota_id) = tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => return Ok(ConnectionAttemptResult { became_healthy: false }),
            _ = shutdown.wait_for(|stopping| *stopping) => return Ok(ConnectionAttemptResult { became_healthy: false }),
            result = preparation => result?,
        };
        log_t!("omikron_connection_success");

        if let Err(error) = self.persist_authenticated_omikron(&endpoint) {
            connection.sender.close().await;
            return Err(error);
        }

        if existing_iota_id.is_none() {
            modify_config(|cfg| cfg.iota_id = Some(connection.client_id));
            log!("Registered with Iota-ID: {}", connection.client_id);
        }

        let generation =
            match self
                .next_attempt
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                }) {
                Ok(generation) => generation,
                Err(_) => {
                    connection.sender.close().await;
                    return Err("connection attempt generation exhausted".into());
                }
            };
        let attempt = Arc::new(ConnectionAttempt {
            generation,
            sender: Arc::new(connection.sender.clone()),
            responses: tau::ResponseCorrelator::new(),
            cancellation: self.cancellation.child_token(),
        });
        let mut active = self.active_attempt.write().await;
        if self.cancellation.is_cancelled() || *shutdown.borrow() {
            attempt.close();
            drop(active);
            attempt.sender.close().await;
            return Ok(ConnectionAttemptResult {
                became_healthy: false,
            });
        }
        let previous = active.replace(attempt.clone());
        drop(active);
        if let Some(previous) = previous {
            previous.close();
            previous.sender.close().await;
        }
        self.set_state(ConnectionState::Connected { identified: true })
            .await;
        self.lifecycle_event(
            LogLevel::Info,
            "connector.attempt.published",
            Some(generation),
            format_args!(""),
        );
        self.password_auth.prune();

        self.run_attempt(Arc::new(connection), attempt).await
    }

    // Discovery/authentication ends before task admission. This boundary owns
    // every connector worker for the published attempt until joined or retained
    // in draining_attempts. It never transfers durable relay ownership.
    pub(super) async fn run_attempt(
        self: Arc<Self>,
        connection: Arc<MTPConnection>,
        attempt: Arc<ConnectionAttempt>,
    ) -> Result<ConnectionAttemptResult, String> {
        let generation = attempt.generation;
        // Start read loop
        let mut scoped = self.as_ref().clone();
        scoped.bound_attempt = Some(attempt.clone());
        scoped.preparation_tasks = Arc::new(Mutex::new(JoinSet::new()));
        let scoped = Arc::new(scoped);
        let read_self = scoped.clone();
        let read_connection = connection.clone();
        let mut read_handle = tokio::spawn(async move {
            read_self.read_loop(read_connection).await;
        });

        log_t!("omikron_authenticated");

        let invitation_self = scoped.clone();
        let invitation_handle = tokio::spawn(async move {
            invitation_self.invitation_loop().await;
        });
        let maintenance_self = scoped;
        let maintenance_handle = tokio::spawn(async move {
            maintenance_self.maintenance_loop(connection).await;
        });

        {
            self.active_tasks.insert("Omikron Listener".to_string());
        }

        // Wait for read loop to complete
        let result = tokio::select! {
            result = &mut read_handle => result,
            _ = attempt.cancellation.cancelled() => {
                // A lost transport need not hold reconnection hostage to an
                // old mutation. Its reader still owns and joins every handler.
                self.lifecycle_event(LogLevel::Info, "connector.attempt.draining", Some(generation), format_args!(""));
                let owner = self.clone();
                self.draining_attempts.lock().await.spawn(async move {
                    if let Err(error) = read_handle.await {
                        owner.worker_failure("reader", Some(generation), &error);
                    }
                });
                Ok(())
            }
        };
        if let Err(error) = &result {
            self.worker_failure("reader", Some(generation), error);
        }
        attempt.close();
        let was_current = {
            let mut active = self.active_attempt.write().await;
            if active
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &attempt))
            {
                *active = None;
                true
            } else {
                false
            }
        };
        if was_current {
            self.set_state(ConnectionState::Disconnected).await;
        }
        {
            self.active_tasks.remove("Omikron Listener");
        }

        attempt.sender.close().await;
        let maintenance_result = maintenance_handle.await;
        let invitation_result = invitation_handle.await;
        if let Err(error) = maintenance_result {
            self.worker_failure("maintenance", Some(generation), &error);
        }
        if let Err(error) = invitation_result {
            self.worker_failure("invitations", Some(generation), &error);
        }
        self.lifecycle_event(
            LogLevel::Info,
            "connector.attempt.closed",
            Some(generation),
            format_args!("was_current={was_current}"),
        );

        match result {
            Ok(()) => Ok(ConnectionAttemptResult {
                became_healthy: true,
            }),
            Err(e) => Err(format!("Read loop error: {}", e)),
        }
    }
}

impl OmikronConnection {
    pub async fn reconnect(self: &Arc<Self>) {
        self.lifecycle_event(
            LogLevel::Info,
            "connector.reconnect.requested",
            None,
            format_args!(""),
        );
        self.clear_auth_failure().await;
        if let Some(attempt) = self.active_attempt.read().await.clone() {
            attempt.close();
        }
        {
            let mut supervisor = self.connection_loop_handle.lock().await;
            if supervisor.as_ref().is_some_and(JoinHandle::is_finished)
                && let Some(handle) = supervisor.take()
                && let Err(error) = handle.await
            {
                self.worker_failure("supervisor", None, &error);
            }
        }
        self.connect().await;
    }
}
