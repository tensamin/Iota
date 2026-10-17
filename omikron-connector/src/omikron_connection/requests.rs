use super::*;

impl OmikronConnection {
    pub async fn send_message(&self, cv: &CommunicationValue) -> Result<(), String> {
        let attempt = self.request_attempt().await?;
        Self::send_on_attempt(&attempt, cv)
            .await
            .map_err(|error| error.to_string())
    }

    pub(super) async fn request_attempt(&self) -> Result<Arc<ConnectionAttempt>, String> {
        let attempt = match &self.bound_attempt {
            Some(attempt) => Some(attempt.clone()),
            None => self.active_attempt.read().await.clone(),
        }
        .ok_or_else(|| "not connected".to_string())?;
        if attempt.cancellation.is_cancelled() {
            return Err("connection closed".into());
        }
        Ok(attempt)
    }

    pub(super) async fn send_on_attempt(
        attempt: &ConnectionAttempt,
        cv: &CommunicationValue,
    ) -> Result<(), mtp::common::CommunicationError> {
        if attempt.cancellation.is_cancelled() || !attempt.sender.is_open() {
            attempt.close();
            return Err(mtp::common::CommunicationError::ClosedLocally);
        }
        log_cv_out!(cv);
        let sent = tokio::select! {
            biased;
            _ = attempt.cancellation.cancelled() => return Err(mtp::common::CommunicationError::ClosedLocally),
            result = attempt.sender.send(cv) => result,
        };
        if let Err(error) = sent {
            attempt.close();
            log!(
                "Omikron attempt {} send failed: {error}",
                attempt.generation
            );
            return Err(error);
        }
        Ok(())
    }

    pub async fn is_connected(&self) -> bool {
        self.state.read().await.is_connected()
    }

    pub async fn is_identified(&self) -> bool {
        self.state.read().await.is_identified()
    }

    pub async fn await_response(
        &self,
        cv: &CommunicationValue,
        timeout_duration: Option<Duration>,
    ) -> Result<CommunicationValue, String> {
        self.await_response_typed(cv, timeout_duration)
            .await
            .map_err(|error| error.to_string())
    }

    pub(super) async fn await_response_typed(
        &self,
        cv: &CommunicationValue,
        timeout_duration: Option<Duration>,
    ) -> Result<CommunicationValue, ConnectorRequestError> {
        let attempt = self
            .request_attempt()
            .await
            .map_err(ConnectorRequestError::Disconnected)?;
        let expected = cv.get_comm_type_enum();
        let timeout = timeout_duration.unwrap_or(Duration::from_secs(10));
        let response = attempt
            .responses
            .exchange(
                cv,
                timeout,
                move |response| expected_response(expected, response),
                |outbound| {
                    let attempt = &attempt;
                    async move { Self::send_on_attempt(attempt, &outbound).await }
                },
            )
            .await;
        if let Err(error) = &response {
            self.lifecycle_event(
                LogLevel::Warn,
                "connector.request.failed",
                Some(attempt.generation),
                format_args!(
                    "kind={expected:?} timeout={}",
                    matches!(error, tau::RequestError::Timeout)
                ),
            );
        }
        let response_cv = response?;
        if cv.is_type(CommunicationType::Relay) {
            return Ok(response_cv);
        }
        if let Some(kind) = response_cv
            .get_comm_type_enum()
            .filter(|kind| tau::is_protocol_error(*kind))
        {
            let reason = response_cv
                .get_data(DataType::Message)
                .as_str()
                .or_else(|| response_cv.get_data(DataType::ErrorType).as_str())
                .unwrap_or("connection error")
                .to_string();
            Err(ConnectorRequestError::Rejected { kind, reason })
        } else {
            Ok(response_cv)
        }
    }

    pub async fn await_connection(&self, timeout_duration: Option<Duration>) -> Result<(), String> {
        let mut rx = self.state_watch_tx.subscribe();
        if rx.borrow().is_connected() {
            return Ok(());
        }

        let timeout = timeout_duration.unwrap_or(CONNECTION_TIMEOUT);

        let result: Result<(), String> = tokio::time::timeout(timeout, async {
            loop {
                rx.changed()
                    .await
                    .map_err(|_| "State watch channel closed".to_string())?;
                if rx.borrow().is_connected() {
                    return Ok(());
                }
            }
        })
        .await
        .map_err(|_| {
            format!(
                "Connection not established within {} seconds",
                timeout.as_secs()
            )
        })?;

        result
    }
}
