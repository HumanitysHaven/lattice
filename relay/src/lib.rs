//! Reference networked relay server (roadmap 1.3 remainder).
//!
//! Enforces exactly the rules [`lattice_core::queue::InMemoryRelay`] already enforces — it
//! *is* an `InMemoryRelay`, shared across connections — but reachable over the network instead
//! of only from in-process tests. Speaks a minimal length-prefixed framing over a plain TCP
//! listener: one signed command per frame in, one framed, postcard-encoded
//! `Result<Response, QueueError>` per frame out — the same shape `lattice-relay-client` speaks.
//!
//! Deliberately **not TLS and not itself a Tor onion service** here: every command is already
//! Ed25519-signed and every blob already AEAD-sealed and length-padded by the caller
//! ([`lattice_core::framing`]), so a network observer between a client and this listener learns
//! nothing from the bytes themselves. The relay-side of Tor reachability (so this process can
//! also be dialled as an onion service) and TLS-for-fingerprint-resistance are deployment
//! concerns layered on top of this listener, not protocol requirements of it. The client-side
//! Tor dial happens in `lattice-relay-client`.
//!
//! This process holds **no user data and no plaintext** (`7.5`): only random queue ids, public
//! keys, and opaque, equal-sized blobs, exactly as the threat model requires of any relay.
//!
//! Exposed as a library (with `lattice-relay`'s `main.rs` as a thin CLI wrapper around
//! [`serve`]) so `lattice-relay-client`'s integration tests can drive this exact server logic
//! over a real loopback socket instead of re-implementing it.

use std::sync::Arc;

use lattice_core::queue::{InMemoryRelay, QueueError, Relay, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Frames larger than this are refused before allocating: comfortably above one signed
/// `Send` command (a ~16 KiB padded blob, see [`lattice_core::framing::BLOCK_SIZE`], plus
/// postcard/signature overhead), so nothing legitimate is ever truncated.
pub const MAX_FRAME: u32 = 64 * 1024;

/// Accept connections on `listener` forever, serving each against the shared `relay` state.
/// Returns only if `accept` itself fails; intended to be run as (or raced against, for
/// shutdown) the process's main loop.
///
/// Deliberately logs nothing about *which* peer a connection was — no address, no
/// timestamp correlated to a peer — even on error. A relay operator who never records that
/// data can't hand it over, lose it in a breach, or use it themselves to link separate
/// connections to one caller; this is as true of logs as it is of the protocol state
/// itself (`7.4`, `S5`).
pub async fn serve(listener: TcpListener, relay: Arc<Mutex<InMemoryRelay>>) -> std::io::Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let relay = Arc::clone(&relay);
        tokio::spawn(async move {
            if let Err(err) = serve_connection(stream, relay).await {
                eprintln!("a connection ended: {err}");
            }
        });
    }
}

/// Serve one client connection: read framed signed commands until the peer disconnects,
/// submitting each to the shared relay and framing back the result.
pub async fn serve_connection(
    mut stream: TcpStream,
    relay: Arc<Mutex<InMemoryRelay>>,
) -> std::io::Result<()> {
    loop {
        let signed_command = match read_frame(&mut stream).await? {
            Some(bytes) => bytes,
            None => return Ok(()), // peer closed cleanly
        };

        let result: Result<Response, QueueError> = relay.lock().await.submit(&signed_command);
        let encoded = postcard::to_allocvec(&result).expect("Result<Response, QueueError> serializes");
        write_frame(&mut stream, &encoded).await?;
    }
}

/// Read one length-prefixed frame (`u32` big-endian length || payload). `Ok(None)` means the
/// peer closed the connection cleanly before sending another frame.
async fn read_frame(stream: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_bytes = [0u8; 4];
    if let Err(err) = stream.read_exact(&mut len_bytes).await {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(err);
    }
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

/// Write one length-prefixed frame.
async fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}
