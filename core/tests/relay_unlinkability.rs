//! Adversarial-relay unlinkability instrumentation (roadmap 1.3 hardening item, `7.4`, `S5`).
//!
//! Models a hostile relay operator who sees everything [`InMemoryRelay`] is ever given —
//! every command, every id, every key, every blob it stores or returns — and tries to use
//! that to link separate queues back to the same real-world user, or to read a queue they
//! were only ever given write access to. These tests assert the properties that make both
//! impossible *from the protocol and data model alone*: no size signal, no exploitable
//! per-connection state (`submit` is stateless per call — nothing about which connection or
//! order a command arrived on ever factors into authorization or storage), and capability
//! separation holding at population scale, not just for one pair of queues.
//!
//! `core/src/queue.rs`'s own test module complements this with the id/key-uniqueness half of
//! the same property (it needs private field access this crate-external test can't reach).
//!
//! **What this does *not* cover:** network-level traffic analysis against a live, observing
//! adversary — circuit timing correlation, connection-pattern fingerprinting, and similar.
//! Protocol-level unlinkability (proven here) is a precondition for that resistance, not a
//! substitute for it; timing-correlation resistance needs live-network instrumentation
//! against real Tor circuits, which no unit or integration test can provide.
//! `lattice-relay-client`'s [`tor::TorRelayClient`](../../relay-client/src/tor.rs) dialing a
//! fresh isolated Tor circuit per command is the *mechanism* meant to defeat that class of
//! attack; see `docs/roadmap.md`'s 1.3 entry for that remaining gap.

use lattice_core::framing;
use lattice_core::queue::{InMemoryRelay, RecipientQueue, SenderCapability};
use lattice_core::transport::Blob;

/// One simulated user: a handful of independent contact relationships, exactly as a real
/// client holds one queue pair per contact.
struct SimulatedUser {
    queues: Vec<(RecipientQueue, SenderCapability)>,
}

fn population(relay: &mut InMemoryRelay, users: usize, queues_per_user: usize) -> Vec<SimulatedUser> {
    (0..users)
        .map(|_| SimulatedUser {
            queues: (0..queues_per_user).map(|_| RecipientQueue::create(relay).unwrap()).collect(),
        })
        .collect()
}

/// Encrypt-shaped traffic in this test is just padding (no ratchet key needed to prove a
/// length-signal property) — real clients additionally seal with a per-message key
/// (`framing::seal`) or an upstream ratchet's own AEAD; either way every blob still ends up
/// this same fixed size, which is what a relay actually observes.
fn wire(payload: &[u8]) -> Blob {
    Blob(framing::pad(payload).unwrap())
}

#[test]
fn interleaved_traffic_from_many_users_never_cross_talks() {
    // A relay operator watching connections arrive in whatever order they arrive, from
    // however many simultaneous users, must not be able to exploit ordering or interleaving
    // to break a queue's isolation — because there is no per-connection state in the
    // protocol for them to exploit in the first place.
    let mut relay = InMemoryRelay::new();
    let population = population(&mut relay, 8, 3);

    // Every user sends one tagged message to every one of their own queues, in an
    // interleaved (round-robin, not per-user-batched) order — the adversarial-relay's-eye
    // view of many simultaneous conversations.
    for round in 0..3u8 {
        for (user_idx, user) in population.iter().enumerate() {
            let (_, cap) = &user.queues[round as usize];
            let tag = vec![user_idx as u8, round];
            cap.send(&mut relay, &wire(&tag)).unwrap();
        }
    }

    // Every queue received exactly its own messages, correctly tagged — nothing arrived on
    // the wrong queue despite the fully interleaved delivery order.
    for (user_idx, user) in population.iter().enumerate() {
        for (round, (queue, _)) in user.queues.iter().enumerate() {
            let delivered = queue.receive(&mut relay).unwrap();
            assert_eq!(delivered.len(), 1, "user {user_idx} queue {round} got the wrong message count");
            let payload = framing::unpad(&delivered[0].0).unwrap();
            assert_eq!(payload, vec![user_idx as u8, round as u8], "cross-talk between users' queues");
        }
    }
}

#[test]
fn every_users_traffic_is_the_same_size_on_the_wire_regardless_of_content() {
    // The relay's only observable per-message signal, absent unlinkability instrumentation,
    // would be length. Across a whole population sending wildly different amounts of data,
    // every blob the relay ever holds must still be one indistinguishable size.
    let mut relay = InMemoryRelay::new();
    let population = population(&mut relay, 5, 1);

    let payload_sizes = [0usize, 1, 500, 4096, framing::MAX_PAYLOAD];
    for (user, &size) in population.iter().zip(payload_sizes.iter()) {
        let (_, cap) = &user.queues[0];
        cap.send(&mut relay, &wire(&vec![0xAB; size])).unwrap();
    }

    assert!(
        relay.resident_blobs().all(|b| b.0.len() == framing::BLOCK_SIZE),
        "a relay watching this population could distinguish users by message length"
    );
}

#[test]
fn a_write_capability_for_one_queue_cannot_read_any_queue_in_a_large_population() {
    // Capability separation must hold at population scale: a sender capability scoped to
    // exactly one queue must not double as a read (or write) capability for anyone else's,
    // even by accident across many queues sharing one relay.
    let mut relay = InMemoryRelay::new();
    let population = population(&mut relay, 6, 2);

    let (_, victim_cap) = &population[0].queues[0];
    victim_cap.send(&mut relay, &wire(b"only the intended recipient should ever see this")).unwrap();

    for (user_idx, user) in population.iter().enumerate() {
        for (queue_idx, (queue, _)) in user.queues.iter().enumerate() {
            if user_idx == 0 && queue_idx == 0 {
                continue; // the legitimate recipient
            }
            // Every other queue in the population is empty: the send only ever reached the
            // one queue its capability was scoped to.
            assert!(
                queue.receive(&mut relay).unwrap().is_empty(),
                "user {user_idx} queue {queue_idx} could see another queue's traffic"
            );
        }
    }

    // The legitimate recipient, and only they, got it.
    let delivered = population[0].queues[0].0.receive(&mut relay).unwrap();
    assert_eq!(delivered.len(), 1);
}
