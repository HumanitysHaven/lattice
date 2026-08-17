//! Manual end-to-end test of the real path: [`TorRelayClient`] talking to a real
//! `lattice-relay` over a real Tor circuit. Run `tor_bootstrap_smoke_test` first if you
//! haven't already, to isolate "is Tor working at all" from "does our protocol work over
//! it".
//!
//! **The relay must be reachable at a real routable address — not `127.0.0.1`.** Tor exit
//! traffic can't reach your own loopback interface, so this needs `lattice-relay` running
//! somewhere with a public IP and an open port (a cheap VPS is enough — it holds no user
//! data, only opaque blobs, so there's nothing sensitive to protect on the box itself).
//!
//! ```text
//! # on the relay host:
//! cargo run -p lattice-relay --release -- 0.0.0.0:7870
//!
//! # on your machine:
//! cargo run -p lattice-relay-client --example tor_relay_round_trip -- <relay-host> 7870
//! ```

use std::env;

use lattice_core::queue::RecipientQueue;
use lattice_core::transport::Blob;
use lattice_relay_client::tor::TorRelayClient;

fn main() {
    let mut args = env::args().skip(1);
    let host = args.next().unwrap_or_else(|| {
        eprintln!("usage: tor_relay_round_trip <relay-host> <relay-port>");
        std::process::exit(1);
    });
    let port: u16 = args
        .next()
        .unwrap_or_else(|| {
            eprintln!("usage: tor_relay_round_trip <relay-host> <relay-port>");
            std::process::exit(1);
        })
        .parse()
        .expect("port must be a number");

    println!("bootstrapping Tor client (first run can take up to ~a minute)...");
    let mut client = TorRelayClient::bootstrap_default(host, port).expect("bootstrap Tor client");
    println!("bootstrapped. creating a queue on the relay over a fresh Tor circuit...");

    let (queue, cap) = RecipientQueue::create(&mut client).expect("create queue over Tor");
    println!("queue created. sending a message over another fresh circuit...");

    let sent = Blob(b"hello over a real Tor circuit".to_vec());
    cap.send(&mut client, &sent).expect("send over Tor");

    println!("receiving over yet another fresh circuit...");
    let delivered = queue.receive(&mut client).expect("receive over Tor");
    assert_eq!(delivered, vec![sent], "the message must survive the round trip byte-for-byte");

    queue.ack(&mut client).expect("ack over Tor");
    println!("success: round-tripped a message through a real relay over real Tor circuits.");
}
