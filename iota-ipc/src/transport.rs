use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io::{Error, ErrorKind, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/* Length-prefixing preserves message boundaries on a byte stream and bounds
 * allocations before JSON is deserialized. */
pub async fn write_msg<W, T>(writer: &mut W, message: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload =
        serde_json::to_vec(message).map_err(|error| Error::new(ErrorKind::InvalidData, error))?;
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
    use super::{read_msg, write_msg};
    use crate::protocol::ClientMessage;

    #[tokio::test]
    async fn round_trips_framed_messages() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let message = ClientMessage::Command {
            seq: 4,
            line: "help".into(),
        };
        write_msg(&mut writer, &message)
            .await
            .expect("write succeeds");
        let received: ClientMessage = read_msg(&mut reader).await.expect("read succeeds");
        assert!(matches!(received, ClientMessage::Command { seq: 4, line } if line == "help"));
    }
}
