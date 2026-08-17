//! A plain, unencrypted-transport TCP [`Relay`] client.
//!
//! **Development and test use only.** This dials the relay directly over TCP with no Tor
//! circuit, so it gives up the one property the anonymous-queue protocol depends on an
//! external transport for: hiding the client's network address from the relay (`7.4`, `S5`).
//! Every command is still Ed25519-signed and every blob still opaque and length-padded, so a
//! network observer still learns nothing from the *bytes* — but the relay (and anyone
//! watching its listener) sees the caller's real IP. Production clients must use
//! [`crate::tor::TorRelayClient`]. This type exists so the wire protocol and
//! [`lattice_relay::main`](https://docs.rs/lattice-relay) server can be exercised in tests and
//! local development without a live Tor connection.

use std::net::SocketAddr;

use tokio::net::TcpStream;
use tokio::runtime::Runtime;

use lattice_core::queue::{QueueError, Relay, Response};

use crate::wire::roundtrip;

/// Dials `addr` fresh over plain TCP for every [`submit`](Relay::submit) call.
pub struct PlainTcpRelayClient {
    addr: SocketAddr,
    runtime: Runtime,
}

impl PlainTcpRelayClient {
    /// Build a client targeting `addr`. Fails only if the local Tokio runtime cannot start.
    pub fn new(addr: SocketAddr) -> Result<Self, QueueError> {
        let runtime = Runtime::new().map_err(|_| QueueError::Transport)?;
        Ok(Self { addr, runtime })
    }
}

impl Relay for PlainTcpRelayClient {
    fn submit(&mut self, signed_command: &[u8]) -> Result<Response, QueueError> {
        let addr = self.addr;
        self.runtime.block_on(async move {
            let mut stream = TcpStream::connect(addr).await.map_err(|_| QueueError::Transport)?;
            roundtrip(&mut stream, signed_command).await
        })
    }
}
