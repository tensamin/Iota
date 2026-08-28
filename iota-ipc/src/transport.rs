use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io::{Error, ErrorKind, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum encoded payload size for a single IPC frame.
///
/// This is a wire-level contract shared by both sides of the connection.
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/* Length-prefixing preserves message boundaries on a byte stream and bounds
 * allocations before JSON is deserialized. */
pub async fn write_msg<W, T>(writer: &mut W, message: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload =
        serde_json::to_vec(message).map_err(|error| Error::new(ErrorKind::InvalidData, error))?;
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "IPC message exceeds limit",
        ));
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| Error::new(ErrorKind::InvalidData, "IPC message is too large"))?;
    writer.write_u32(len).await?;
    writer.write_all(&payload).await?;
    writer.flush().await
}

pub async fn read_msg<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let len = reader.read_u32().await? as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "IPC message exceeds limit",
        ));
    }
    let mut payload = vec![0; len];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload).map_err(|error| Error::new(ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::{MAX_MESSAGE_SIZE, read_msg, write_msg};
    use crate::protocol::{ClientMessage, LocalRequest, RequestEnvelope};

    #[tokio::test]
    async fn round_trips_framed_messages() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let message = ClientMessage::Request(RequestEnvelope {
            request_id: 4,
            protocol_version: 2,
            request: LocalRequest::GetStatus,
        });
        write_msg(&mut writer, &message)
            .await
            .expect("write succeeds");
        let received: ClientMessage = read_msg(&mut reader).await.expect("read succeeds");
        assert!(matches!(received, ClientMessage::Request(req) if req.request_id == 4));
    }

    #[tokio::test]
    async fn write_rejects_message_above_frame_limit() {
        let (mut writer, _reader) = tokio::io::duplex(MAX_MESSAGE_SIZE + 16);
        let message = "x".repeat(MAX_MESSAGE_SIZE + 1);

        let error = write_msg(&mut writer, &message)
            .await
            .expect_err("oversized payload must be rejected before framing");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds limit"));
    }

    #[tokio::test]
    async fn read_rejects_frame_above_limit_before_allocating_payload() {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        tokio::io::AsyncWriteExt::write_u32(&mut writer, (MAX_MESSAGE_SIZE + 1) as u32)
            .await
            .expect("length prefix write succeeds");

        let error = read_msg::<_, ClientMessage>(&mut reader)
            .await
            .expect_err("oversized frame must be rejected");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
