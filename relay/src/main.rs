//! CLI entry point for the reference relay server. See `lib.rs` for the protocol/behaviour.

use std::env;
use std::sync::Arc;

use lattice_core::queue::InMemoryRelay;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:7870".to_string());
    let listener = TcpListener::bind(&addr).await?;
    println!("lattice-relay listening on {addr}");

    let relay = Arc::new(Mutex::new(InMemoryRelay::new()));

    tokio::select! {
        result = lattice_relay::serve(listener, relay) => result,
        _ = tokio::signal::ctrl_c() => {
            println!("shutting down");
            Ok(())
        }
    }
}
