use mtp::codec::CommunicationValue;
use std::future::Future;
use std::time::Duration;

/// Unified interface for all connection types (Omikron, Direct, future modes).
///
/// Provides the common messaging API that the rest of the codebase uses,
/// regardless of whether the connection goes through Omikron or is direct.
pub trait ConnectionHandler: Send + Sync {
    /// Send a message to the remote end.
    fn send_message(
        &self,
        cv: &CommunicationValue,
    ) -> impl Future<Output = Result<(), String>> + Send;

    /// Send a message and wait for a correlated response.
    ///
    /// The implementation correlates requests/responses by message ID and
    /// enforces the given `timeout`. Returns an error on timeout or if the
    /// connection drops while waiting.
    fn await_response(
        &self,
        cv: &CommunicationValue,
        timeout: Option<Duration>,
    ) -> impl Future<Output = Result<CommunicationValue, String>> + Send;

    /// Returns `true` when the connection is alive and ready for traffic.
    fn is_connected(&self) -> impl Future<Output = bool> + Send;

    /// Returns `true` when the connection has completed identification /
    /// registration and is fully operational.
    fn is_identified(&self) -> impl Future<Output = bool> + Send;

    /// Gracefully tear down the connection.
    fn stop(&self) -> impl Future<Output = ()> + Send;
}
