//! Manual smoke test: proves *this machine* can bootstrap a real Tor connection via
//! `arti-client` and build a working circuit. This is the one thing that could not be
//! verified in the sandboxed environment that built `lattice-relay-client` — its network
//! egress to Tor infrastructure was firewalled — so run this once on a normal machine
//! before trusting [`lattice_relay_client::tor::TorRelayClient`].
//!
//! Deliberately independent of lattice's own protocol/relay: it bootstraps Arti and opens
//! a circuit straight to a well-known public HTTPS host, so a failure here points at Tor
//! connectivity itself rather than anything in this crate.
//!
//! ```text
//! cargo run -p lattice-relay-client --example tor_bootstrap_smoke_test
//! ```
//!
//! Expect this to take anywhere from a few seconds to roughly a minute the *first* run —
//! Arti has to fetch and validate Tor directory information, which it then caches (in the
//! platform default state/cache dirs) for faster bootstraps next time.

use arti_client::{TorClient, TorClientConfig};

#[tokio::main]
async fn main() {
    println!("bootstrapping Tor client (first run can take up to ~a minute)...");
    let config = TorClientConfig::default();
    let tor = TorClient::create_bootstrapped(config).await.expect(
        "failed to bootstrap a Tor connection — check this machine's network egress \
         allows reaching the Tor network (this is exactly what the sandbox that built \
         this crate could not do)",
    );
    println!("bootstrapped. opening a circuit to example.com:443 over Tor...");

    let mut stream = tor.connect(("example.com", 443)).await.expect("failed to connect over Tor");

    use tokio::io::AsyncWriteExt;
    stream.write_all(b"HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n").await.expect("write over Tor stream");
    stream.flush().await.expect("flush");

    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.expect("read over Tor stream");
    let head = String::from_utf8_lossy(&buf[..n]);

    println!("received {n} bytes over the Tor circuit, starting: {head:?}");
    assert!(head.starts_with("HTTP/"), "expected an HTTP response over the Tor circuit");
    println!("success: this machine can bootstrap Arti and route traffic through Tor.");
}
