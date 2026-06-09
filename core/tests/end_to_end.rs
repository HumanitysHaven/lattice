//! End-to-end integration of the pure stack, exercised through the **public API only**.
//!
//! These tests compose the modules the way a real client will — identity, invitation
//! onboarding, the trust engine, fixed-size framing, and an untrusted relay — and assert the
//! security properties that emerge from the composition (not just each unit in isolation):
//!
//! - an invited contact can be messaged, and the message survives a round-trip through a
//!   relay that only ever holds opaque, equal-sized blobs;
//! - the relay learns nothing from length (a one-byte ack and a full message are the same
//!   size) and never sees plaintext;
//! - a party without the channel key cannot read a blob;
//! - trust earned through signed vouches unlocks higher capabilities.
//!
//! The per-message key is a fixed stand-in for the Double-Ratchet message key that milestone
//! 1.4 will supply; everything else is the real implementation.

use std::collections::HashMap;

use lattice_core::framing::{self, SEALED_LEN};
use lattice_core::identity::Identity;
use lattice_core::invite::InviteBook;
use lattice_core::transport::{Blob, QueueAddr, Transport, TransportError};
use lattice_core::trust::{AddedVia, Contact, Tier, TrustGraph, TrustParams};
use lattice_core::vouching::SignedVouch;

const NOW: i64 = 1_900_000_000;
const HOUR: i64 = 3_600;

/// An in-memory stand-in for an untrusted SMP-style relay, modelling exactly what a real
/// relay can observe and do: it holds opaque blobs in per-queue mailboxes keyed by an opaque
/// address, and can neither read nor attribute them. It additionally records every blob
/// length it has handled so tests can assert the relay's view carries no metadata.
#[derive(Default)]
struct MemoryRelay {
    queues: HashMap<Vec<u8>, Vec<Blob>>,
    observed_lengths: Vec<usize>,
}

impl MemoryRelay {
    fn new() -> Self {
        Self::default()
    }

    /// Every blob length this relay has ever been asked to store.
    fn observed_lengths(&self) -> &[usize] {
        &self.observed_lengths
    }

    /// All blobs currently resident in any queue (what a relay seizure would expose).
    fn resident_blobs(&self) -> impl Iterator<Item = &Blob> {
        self.queues.values().flatten()
    }
}

impl Transport for MemoryRelay {
    fn send(&mut self, queue: &QueueAddr, blob: &Blob) -> Result<(), TransportError> {
        self.observed_lengths.push(blob.0.len());
        self.queues.entry(queue.0.clone()).or_default().push(blob.clone());
        Ok(())
    }

    fn receive(&mut self, queue: &QueueAddr) -> Result<Vec<Blob>, TransportError> {
        Ok(self.queues.get_mut(&queue.0).map(std::mem::take).unwrap_or_default())
    }
}

/// Stand-in for the symmetric message key the Double Ratchet (1.4) will derive per message.
const CHANNEL_KEY: [u8; 32] = [0x42; 32];

/// A random-looking, identity-free queue address. In production this is random per contact;
/// here a fixed opaque value is enough and deliberately bears no relation to any identity.
fn bob_queue() -> QueueAddr {
    QueueAddr(b"opaque-receive-queue-for-bob".to_vec())
}

#[test]
fn invite_then_encrypted_delivery_through_an_untrusted_relay() {
    // Alice onboards Bob by personal invitation (the only entry path).
    let alice = Identity::generate("alice").unwrap();
    let bob = Identity::generate("bob").unwrap();

    let mut book = InviteBook::new();
    let token = book.issue(HOUR, NOW).unwrap();
    // Bob receives the token out-of-band and redeems it.
    let grant = book.redeem(&token, NOW).unwrap();
    let bob_contact = grant.into_contact(bob.verifying_key().local_id());

    let mut alice_graph = TrustGraph::new(TrustParams::default());
    alice_graph.upsert_contact(bob_contact);
    assert_eq!(
        alice_graph.recompute_tier(&bob.verifying_key().local_id(), NOW),
        Tier::Invited,
        "an invitee onboards at Tier 0"
    );
    let _ = &alice; // Alice's identity drives later milestones (ratchet handshake); unused here.

    // Alice sends Bob a message: pad+seal into an opaque blob, hand it to the relay.
    let mut relay = MemoryRelay::new();
    let plaintext = b"the meeting moved to 7pm, use the back entrance".to_vec();
    let blob = framing::seal(&CHANNEL_KEY, &plaintext).unwrap();
    relay.send(&bob_queue(), &blob).unwrap();

    // Bob drains his queue and opens the blob.
    let delivered = relay.receive(&bob_queue()).unwrap();
    assert_eq!(delivered.len(), 1, "exactly one blob waiting");
    let recovered = framing::open(&CHANNEL_KEY, &delivered[0]).unwrap();
    assert_eq!(recovered, plaintext, "Bob recovers Alice's message verbatim");

    // The queue is now empty (messages are drained on receive).
    assert!(relay.receive(&bob_queue()).unwrap().is_empty());
}

#[test]
fn the_relay_sees_only_equal_sized_opaque_blobs() {
    let mut relay = MemoryRelay::new();

    // A terse ack and a near-maximum message.
    let ack = framing::seal(&CHANNEL_KEY, b"k").unwrap();
    let long = framing::seal(&CHANNEL_KEY, &vec![0u8; framing::MAX_PAYLOAD]).unwrap();
    relay.send(&bob_queue(), &ack).unwrap();
    relay.send(&bob_queue(), &long).unwrap();

    // Every blob the relay handled is exactly the fixed sealed size: length leaks nothing.
    assert!(relay.observed_lengths().iter().all(|&n| n == SEALED_LEN));
    assert_eq!(relay.observed_lengths().len(), 2);
}

#[test]
fn a_seized_relay_exposes_no_plaintext() {
    let mut relay = MemoryRelay::new();
    let secret = b"SAFEHOUSE-ADDR-221B-BAKER-ST";
    let blob = framing::seal(&CHANNEL_KEY, secret).unwrap();
    relay.send(&bob_queue(), &blob).unwrap();

    // Whatever the relay holds, the plaintext never appears in it.
    for held in relay.resident_blobs() {
        assert!(
            !held.0.windows(secret.len()).any(|w| w == secret),
            "plaintext must never be visible to the relay"
        );
    }
}

#[test]
fn a_party_without_the_channel_key_cannot_read_a_blob() {
    let blob = framing::seal(&CHANNEL_KEY, b"for bob's eyes only").unwrap();
    let wrong_key = [0x43; 32];
    assert!(
        framing::open(&wrong_key, &blob).is_err(),
        "only the holder of the channel key can open the blob"
    );
}

#[test]
fn signed_vouches_promote_a_contact_and_unlock_group_chat() {
    // Two contacts Alice trusts directly (manual floor) each vouch for a newcomer; once the
    // signed vouches are verified at the boundary and fed to the engine, the newcomer reaches
    // Tier 2 (Trusted), which unlocks group chat — capability gating emerging from identity +
    // vouching + trust composed through the public API.
    let anchor_a = Identity::generate("anchor-a").unwrap();
    let anchor_b = Identity::generate("anchor-b").unwrap();
    let newcomer = Identity::generate("newcomer").unwrap();
    let newcomer_id = newcomer.verifying_key().local_id();

    let mut graph = TrustGraph::new(TrustParams::default());
    graph.upsert_contact(
        Contact::new(anchor_a.verifying_key().local_id(), AddedVia::Invite).with_manual_floor(Tier::Core),
    );
    graph.upsert_contact(
        Contact::new(anchor_b.verifying_key().local_id(), AddedVia::Invite).with_manual_floor(Tier::Core),
    );
    graph.upsert_contact(Contact::new(newcomer_id, AddedVia::VouchedIntro));

    // Before any vouches, the newcomer cannot join group chats.
    graph.recompute_all(NOW);
    assert!(!graph.contact(&newcomer_id).unwrap().tier.capabilities().group_chat);

    for (voucher, n) in [(&anchor_a, 1u8), (&anchor_b, 2u8)] {
        let mut nonce = [0u8; 16];
        nonce[0] = n;
        let signed = SignedVouch::issue(voucher, &newcomer.verifying_key(), 3, NOW, nonce);
        let vouch = signed.verify().expect("anchor vouches verify");
        graph.add_vouch(vouch);
    }
    graph.recompute_all(NOW);

    let caps = graph.contact(&newcomer_id).unwrap().tier.capabilities();
    assert_eq!(graph.contact(&newcomer_id).unwrap().tier, Tier::Trusted);
    assert!(caps.group_chat, "a Trusted contact may join group chats");
    assert!(caps.direct_message);
}
