//! The length-prefixed framing shared by every transport this crate implements: `u32`
//! big-endian length || payload. One frame carries one signed command out, and one frame
//! carries the postcard-encoded `Result<Response, QueueError>` back — the same shape
//! `lattice-relay` speaks on the server side.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use lattice_core::queue::{QueueError, Response};

/// Frames larger than this are refused before allocating. Matches `lattice-relay`'s limit:
/// comfortably above one signed `Send` command (a ~16 KiB padded blob, see
/// [`lattice_core::framing::BLOCK_SIZE`], plus postcard/signature overhead).
pub const MAX_FRAME: u32 = 64 * 1024;

/// Write one length-prefixed frame and flush it.
pub async fn write_frame<S: AsyncWrite + Unpin>(stream: &mut S, payload: &[u8]) -> Result<(), QueueError> {
    let len = u32::try_from(payload.len()).map_err(|_| QueueError::Transport)?;
    stream.write_all(&len.to_be_bytes()).await.map_err(|_| QueueError::Transport)?;
    stream.write_all(payload).await.map_err(|_| QueueError::Transport)?;
    stream.flush().await.map_err(|_| QueueError::Transport)
}

/// Read exactly one length-prefixed frame.
pub async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, QueueError> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await.map_err(|_| QueueError::Transport)?;
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_FRAME {
        return Err(QueueError::Transport);
    }
    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload).await.map_err(|_| QueueError::Transport)?;
    Ok(payload)
}

/// Send one already-signed command over a freshly-connected stream and return the relay's
/// decoded reply: the one request/response exchange every transport in this crate performs
/// per [`lattice_core::queue::Relay::submit`] call, over whatever stream it was handed.
pub async fn roundtrip<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    signed_command: &[u8],
) -> Result<Response, QueueError> {
    write_frame(stream, signed_command).await?;
    let reply = read_frame(stream).await?;
    postcard::from_bytes::<Result<Response, QueueError>>(&reply).map_err(|_| QueueError::Malformed)?
}
