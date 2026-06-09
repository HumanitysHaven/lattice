//! End-to-end integration of the pure stack, exercised through the **public API only**.
//!
//! These tests compose the modules the way a real client will — identity, invitation
//! onboarding, the trust engine, the Olm Double Ratchet, fixed-size framing, and an untrusted
//! relay — and assert the security properties that emerge from the composition:
//!
//! - an invited contact can establish a forward-secret session and exchange messages that
//!   survive a round-trip through a relay holding only opaque, equal-sized blobs;
//! - the relay learns nothing from length (even the handshake message is the same size as a
//!   one-byte reply) and never sees plaintext;
//! - a third party who captures a blob cannot decrypt it;
//! - trust earned through signed vouches unlocks higher capabilities.

use std::collections::HashMap;

use lattice_core::framing::{self, BLOCK_SIZE};
use lattice_core::identity::Identity;
use lattice_core::invite::InviteBook;
use lattice_core::messaging::{Device, OneToOneSession, PlainMessage, Session};
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

/// A random-looking, identity-free queue address. In production this is random per contact;
/// here a fixed opaque value is enough and deliberately bears no relation to any identity.
fn bob_queue() -> QueueAddr {
    QueueAddr(b"opaque-receive-queue-for-bob".to_vec())
}

/// Encrypt with the ratchet, then pad to a fixed-size block — the full client send path.
fn seal_for_wire(session: &mut Session, msg: &PlainMessage) -> Blob {
    let ciphertext = session.encrypt(msg).expect("ratchet encrypt");
    Blob(framing::pad(&ciphertext).expect("pad to block"))
}

/// Unpad a received block, then decrypt with the ratchet — the full client receive path.
fn open_from_wire(session: &mut Session, blob: &Blob) -> PlainMessage {
    let ciphertext = framing::unpad(&blob.0).expect("unpad block");
    session.decrypt(&ciphertext).expect("ratchet decrypt")
}

#[test]
fn invite_then_forward_secret_delivery_through_an_untrusted_relay() {
    // Alice onboards Bob by personal invitation (the only entry path).
    let alice_id = Identity::generate("alice").unwrap();
    let bob_id = Identity::generate("bob").unwrap();

    let mut book = InviteBook::new();
    let token = book.issue(HOUR, NOW).unwrap();
    let grant = book.redeem(&token, NOW).unwrap();
    let bob_contact = grant.into_contact(bob_id.verifying_key().local_id());

    let mut alice_graph = TrustGraph::new(TrustParams::default());
    alice_graph.upsert_contact(bob_contact);
    assert_eq!(
        alice_graph.recompute_tier(&bob_id.verifying_key().local_id(), NOW),
        Tier::Invited,
        "an invitee onboards at Tier 0"
    );
    let _ = &alice_id; // signing identity drives vouching/anchoring, not this message path.

    // Alongside the invite handshake, Bob publishes a one-time pre-key bundle.
    let alice = Device::new();
    let mut bob = Device::new();
    let bundle = bob.publish_prekey_bundle();

    // Alice starts a session and sends Bob a message through the relay.
    let mut alice_session = alice.start_session(&bundle).unwrap();
    let mut relay = MemoryRelay::new();
    let message = PlainMessage::new(b"the meeting moved to 7pm, use the back entrance".to_vec());
    relay.send(&bob_queue(), &seal_for_wire(&mut alice_session, &message)).unwrap();

    // Bob drains his queue, unpads, and accepts the session from the first (pre-key) message.
    let delivered = relay.receive(&bob_queue()).unwrap();
    assert_eq!(delivered.len(), 1);
    let first_wire = framing::unpad(&delivered[0].0).unwrap();
    let (mut bob_session, received) = bob.accept_session(alice.identity_key(), &first_wire).unwrap();
    assert_eq!(received, message, "Bob recovers Alice's first message verbatim");

    // Bob replies; the channel is now fully bidirectional and forward-secret.
    relay
        .send(&bob_queue(), &seal_for_wire(&mut bob_session, &PlainMessage::new(b"understood".to_vec())))
        .unwrap();
    let reply_blobs = relay.receive(&bob_queue()).unwrap();
    assert_eq!(open_from_wire(&mut alice_session, &reply_blobs[0]).body, b"understood");

    // Everything the relay handled was a fixed-size block.
    assert!(relay.observed_lengths().iter().all(|&n| n == BLOCK_SIZE));
}

#[test]
fn the_relay_sees_only_equal_sized_opaque_blobs() {
    let alice = Device::new();
    let mut bob = Device::new();
    let bundle = bob.publish_prekey_bundle();
    let mut alice_session = alice.start_session(&bundle).unwrap();

    let mut relay = MemoryRelay::new();
    // The handshake (pre-key) message, a terse ack, and a multi-kilobyte message.
    relay.send(&bob_queue(), &seal_for_wire(&mut alice_session, &PlainMessage::new(b"k".to_vec()))).unwrap();
    relay.send(&bob_queue(), &seal_for_wire(&mut alice_session, &PlainMessage::new(b"y".to_vec()))).unwrap();
    relay
        .send(&bob_queue(), &seal_for_wire(&mut alice_session, &PlainMessage::new(vec![7u8; 8192])))
        .unwrap();

    // A handshake, a 1-byte ack, and an 8 KiB message are all indistinguishable by size.
    assert_eq!(relay.observed_lengths(), [BLOCK_SIZE, BLOCK_SIZE, BLOCK_SIZE]);
}

#[test]
fn a_seized_relay_exposes_no_plaintext() {
    let alice = Device::new();
    let mut bob = Device::new();
    let bundle = bob.publish_prekey_bundle();
    let mut alice_session = alice.start_session(&bundle).unwrap();

    let mut relay = MemoryRelay::new();
    let secret = b"SAFEHOUSE-ADDR-221B-BAKER-ST";
    relay
        .send(&bob_queue(), &seal_for_wire(&mut alice_session, &PlainMessage::new(secret.to_vec())))
        .unwrap();

    for held in relay.resident_blobs() {
        assert!(
            !held.0.windows(secret.len()).any(|w| w == secret),
            "plaintext must never be visible to the relay"
        );
    }
}

#[test]
fn a_third_party_who_captures_a_blob_cannot_read_it() {
    let alice = Device::new();
    let mut bob = Device::new();
    let bundle = bob.publish_prekey_bundle();
    let mut alice_session = alice.start_session(&bundle).unwrap();

    let mut relay = MemoryRelay::new();
    relay
        .send(&bob_queue(), &seal_for_wire(&mut alice_session, &PlainMessage::new(b"for bob only".to_vec())))
        .unwrap();
    let captured = relay.receive(&bob_queue()).unwrap().remove(0);
    let captured_wire = framing::unpad(&captured.0).unwrap();

    // Eve, with her own unrelated session, cannot decrypt Alice's captured ciphertext.
    let mut eve_bob = Device::new();
    let eve_bundle = eve_bob.publish_prekey_bundle();
    let eve = Device::new();
    let mut eve_session = eve.start_session(&eve_bundle).unwrap();
    let intro = eve_session.encrypt(&PlainMessage::new(b"hi".to_vec())).unwrap();
    let (mut eve_bob_session, _) = eve_bob.accept_session(eve.identity_key(), &intro).unwrap();

    assert!(
        eve_bob_session.decrypt(&captured_wire).is_err(),
        "a foreign session must not decrypt a captured blob"
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

    graph.recompute_all(NOW);
    assert!(!graph.contact(&newcomer_id).unwrap().tier.capabilities().group_chat);

    for (voucher, n) in [(&anchor_a, 1u8), (&anchor_b, 2u8)] {
        let mut nonce = [0u8; 16];
        nonce[0] = n;
        let signed = SignedVouch::issue(voucher, &newcomer.verifying_key(), 3, NOW, nonce);
        graph.add_vouch(signed.verify().expect("anchor vouches verify"));
    }
    graph.recompute_all(NOW);

    let caps = graph.contact(&newcomer_id).unwrap().tier.capabilities();
    assert_eq!(graph.contact(&newcomer_id).unwrap().tier, Tier::Trusted);
    assert!(caps.group_chat, "a Trusted contact may join group chats");
    assert!(caps.direct_message);
}
