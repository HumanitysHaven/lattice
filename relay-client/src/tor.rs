//! The production [`Relay`] client: reaches the relay over Tor, so the relay never learns the
//! caller's real network address (`7.4`, `S5`). Built on `arti-client`, the Tor Project's own
//! pure-Rust client — no home-grown transport, matching the crypto layers' "audited components
//! only" bar, and no dependency on a system-installed `tor` binary (`7.7`).
//!
//! Every [`submit`](Relay::submit) call dials through
//! [`isolated_client`](TorClient::isolated_client): a fresh Tor circuit, sharing no path with
//! any other call. This is a strict superset of the roadmap's "per-queue connections" —
//! distinct commands are unlinkable to a relay-side or path-side observer even when they
//! target the same queue, at the cost of the extra circuit-build latency per call. Bootstrapping
//! the Tor connection itself happens once, in [`TorRelayClient::bootstrap`], and is reused.

use std::sync::Arc;

use arti_client::config::TorClientConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use tokio::runtime::Runtime;
use tor_rtcompat::PreferredRuntime;

use lattice_core::queue::{QueueError, Relay, Response};

use crate::wire::roundtrip;

/// Reaches one relay's `host:port` over a fresh, isolated Tor circuit per command.
pub struct TorRelayClient {
    tor: Arc<TorClient<PreferredRuntime>>,
    host: String,
    port: u16,
    runtime: Runtime,
}

impl TorRelayClient {
    /// Bootstrap a Tor connection (fetches directory material; reuses the cache at
    /// `state_dir`/`cache_dir` when available) and target it at the relay's `host:port`. This
    /// is the slow, one-time setup — subsequent [`submit`](Relay::submit) calls only pay for a
    /// fresh circuit, not a fresh bootstrap.
    pub fn bootstrap(
        state_dir: &std::path::Path,
        cache_dir: &std::path::Path,
        relay_host: impl Into<String>,
        relay_port: u16,
    ) -> Result<Self, QueueError> {
        let runtime = Runtime::new().map_err(|_| QueueError::Transport)?;
        let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
            .build()
            .map_err(|_| QueueError::Transport)?;
        let tor =
            runtime.block_on(TorClient::create_bootstrapped(config)).map_err(|_| QueueError::Transport)?;
        Ok(Self { tor, host: relay_host.into(), port: relay_port, runtime })
    }

    /// As [`bootstrap`](Self::bootstrap), but with the default [`TorClientConfig`] (Arti's own
    /// default state/cache locations) rather than caller-chosen directories.
    pub fn bootstrap_default(relay_host: impl Into<String>, relay_port: u16) -> Result<Self, QueueError> {
        let runtime = Runtime::new().map_err(|_| QueueError::Transport)?;
        let tor = runtime
            .block_on(TorClient::create_bootstrapped(TorClientConfig::default()))
            .map_err(|_| QueueError::Transport)?;
        Ok(Self { tor, host: relay_host.into(), port: relay_port, runtime })
    }
}

impl Relay for TorRelayClient {
    fn submit(&mut self, signed_command: &[u8]) -> Result<Response, QueueError> {
        let host = self.host.clone();
        let port = self.port;
        let tor = self.tor.isolated_client();
        self.runtime.block_on(async move {
            let mut stream = tor.connect((host.as_str(), port)).await.map_err(|_| QueueError::Transport)?;
            roundtrip(&mut stream, signed_command).await
        })
    }
}
