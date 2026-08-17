//! Proves the networked edge itself: `queue::RecipientQueue`/`SenderCapability` — already
//! tested against the in-process `InMemoryRelay` in `lattice-core` — work unmodified against
//! [`PlainTcpRelayClient`] talking to the real `lattice-relay` server logic over a real loopback
//! TCP socket. This is deliberately the dev/test transport (no Tor circuit — see
//! `plain.rs`'s docs); it exists to exercise the length-prefixed wire framing and the
//! client/server composition, which [`crate::tor::TorRelayClient`] shares.

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::thread;

use lattice_core::queue::{InMemoryRelay, RecipientQueue};
use lattice_core::transport::Blob;
use lattice_relay_client::plain::PlainTcpRelayClient;
use tokio::sync::Mutex;

/// Start `lattice_relay::serve` on a background OS thread with its own runtime, bound to an
/// OS-assigned loopback port, and return that port's address. The server runs for the life of
/// the test process; nothing needs to shut it down for a test binary.
fn spawn_relay() -> SocketAddr {
    let std_listener = StdTcpListener::bind("127.0.0.1:0").expect("bind loopback");
    std_listener.set_nonblocking(true).expect("set nonblocking for tokio to adopt");
    let addr = std_listener.local_addr().expect("local_addr");

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("server runtime");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(std_listener).expect("adopt std listener");
            let relay = Arc::new(Mutex::new(InMemoryRelay::new()));
            let _ = lattice_relay::serve(listener, relay).await;
        });
    });

    addr
}

#[test]
fn create_send_receive_and_ack_round_trip_over_a_real_socket() {
    let addr = spawn_relay();
    let mut client = PlainTcpRelayClient::new(addr).expect("build client");

    let (queue, cap) = RecipientQueue::create(&mut client).expect("create queue over the network");

    let blob = Blob(vec![0xAAu8; 4096]);
    cap.send(&mut client, &blob).expect("send over the network");

    let delivered = queue.receive(&mut client).expect("receive over the network");
    assert_eq!(delivered, vec![blob], "the exact bytes survive a real TCP round trip");

    queue.ack(&mut client).expect("ack over the network");
    assert!(queue.receive(&mut client).expect("receive after ack").is_empty());
}

#[test]
fn state_persists_across_separate_connections_to_the_same_relay() {
    // Each `submit` call opens a fresh connection (matching the per-command isolation the Tor
    // client uses for unlinkability); this proves the relay's queue state is shared across
    // connections rather than accidentally scoped to one, since every operation below is its
    // own TCP connection to the same server thread.
    let addr = spawn_relay();
    let mut recipient_client = PlainTcpRelayClient::new(addr).expect("recipient client");
    let mut sender_client = PlainTcpRelayClient::new(addr).expect("sender client");

    let (queue, cap) = RecipientQueue::create(&mut recipient_client).expect("create queue");
    cap.send(&mut sender_client, &Blob(vec![0x42u8; 16])).expect("send from a different connection");

    let delivered = queue.receive(&mut recipient_client).expect("receive from yet another connection");
    assert_eq!(delivered, vec![Blob(vec![0x42u8; 16])]);
}
