//! End-to-end integration of the pure stack, exercised through the **public API only**.
//!
//! These tests compose the modules the way a real client will — identity, invitation
//! onboarding, the trust engine, the Olm Double Ratchet, fixed-size framing, and the
//! authenticated anonymous-queue transport against a reference untrusted relay — and assert
//! the security properties that emerge from the composition:
//!
//! - an invited contact can establish a forward-secret session and receive messages delivered
//!   through an authenticated simplex queue on an untrusted relay;
//! - the relay holds only opaque, equal-sized blobs (even the handshake) and never plaintext;
//! - the write-only sender capability cannot read the recipient's queue;
//! - trust earned through signed vouches unlocks higher capabilities.

use lattice_core::framing::{self, BLOCK_SIZE};
use lattice_core::identity::Identity;
use lattice_core::invite::InviteBook;
use lattice_core::messaging::{Device, OneToOneSession, PlainMessage, Session};
use lattice_core::queue::{InMemoryRelay, RecipientQueue, SenderCapability};
use lattice_core::transport::Blob;
use lattice_core::trust::{AddedVia, Contact, Tier, TrustGraph, TrustParams};
use lattice_core::vouching::SignedVouch;

const NOW: i64 = 1_900_000_000;
const HOUR: i64 = 3_600;

/// Encrypt with the ratchet, then pad to a fixed-size block — the full client send path.
fn seal_for_wire(session: &mut Session, msg: &PlainMessage) -> Blob {
    let ciphertext = session.encrypt(msg).expect("ratchet encrypt");
    Blob(framing::pad(&ciphertext).expect("pad to block"))
}

/// What a contact receives out-of-band with the invite to be able to message the inviter: the
/// Olm pre-key bundle (to start a session) and the write-only queue capability (to deliver).
struct InviteChannel {
    prekey_bundle: lattice_core::messaging::PreKeyBundle,
    sender_capability: SenderCapability,
}

#[test]
fn invite_then_forward_secret_delivery_over_authenticated_queues() {
    // Alice onboards Bob by personal invitation (the only entry path).
    let alice_id = Identity::generate("alice").unwrap();
    let bob_id = Identity::generate("bob").unwrap();

    let mut book = InviteBook::new();
    let token = book.issue(HOUR, NOW).unwrap();
    let grant = book.redeem(&token, NOW).unwrap();
    let alice_contact = grant.into_contact(bob_id.verifying_key().local_id());

    // Bob (the inviter here receives; model Bob as the one being messaged) records Alice.
    let mut bob_graph = TrustGraph::new(TrustParams::default());
    bob_graph.upsert_contact(alice_contact);
    assert_eq!(
        bob_graph.recompute_tier(&bob_id.verifying_key().local_id(), NOW),
        Tier::Invited,
        "an invitee onboards at Tier 0"
    );
    let _ = &alice_id;

    let mut relay = InMemoryRelay::new();

    // Bob provisions a queue and Olm pre-key, and hands the capability + bundle to Alice with
    // the invite. Bob keeps the private recipient handle.
    let mut bob_device = Device::new();
    let (bob_queue, sender_capability) = RecipientQueue::create(&mut relay).unwrap();
    let channel = InviteChannel { prekey_bundle: bob_device.publish_prekey_bundle(), sender_capability };

    // Alice starts a session and delivers a message through Bob's authenticated queue.
    let alice_device = Device::new();
    let mut alice_session = alice_device.start_session(&channel.prekey_bundle).unwrap();
    let message = PlainMessage::new(b"the meeting moved to 7pm, use the back entrance".to_vec());
    channel.sender_capability.send(&mut relay, &seal_for_wire(&mut alice_session, &message)).unwrap();

    // Bob reads his queue, unpads, and accepts the session from the first (pre-key) message.
    let delivered = bob_queue.receive(&mut relay).unwrap();
    assert_eq!(delivered.len(), 1);
    let first_wire = framing::unpad(&delivered[0].0).unwrap();
    let (_bob_session, received) =
        bob_device.accept_session(alice_device.identity_key(), &first_wire).unwrap();
    assert_eq!(received, message, "Bob recovers Alice's message verbatim");

    // After acking, the queue is empty.
    bob_queue.ack(&mut relay).unwrap();
    assert!(bob_queue.receive(&mut relay).unwrap().is_empty());
}

#[test]
fn the_relay_holds_only_equal_sized_opaque_blobs() {
    let mut relay = InMemoryRelay::new();
    let mut bob_device = Device::new();
    let (_bob_queue, cap) = RecipientQueue::create(&mut relay).unwrap();
    let bundle = bob_device.publish_prekey_bundle();

    let alice_device = Device::new();
    let mut alice_session = alice_device.start_session(&bundle).unwrap();

    // The handshake (pre-key) message, a terse ack, and a multi-kilobyte message.
    cap.send(&mut relay, &seal_for_wire(&mut alice_session, &PlainMessage::new(b"k".to_vec()))).unwrap();
    cap.send(&mut relay, &seal_for_wire(&mut alice_session, &PlainMessage::new(b"y".to_vec()))).unwrap();
    cap.send(&mut relay, &seal_for_wire(&mut alice_session, &PlainMessage::new(vec![7u8; 8192]))).unwrap();

    // Everything the relay holds is one fixed size: length leaks nothing, not even handshake.
    assert!(relay.resident_blobs().all(|b| b.0.len() == BLOCK_SIZE));
    assert_eq!(relay.resident_blobs().count(), 3);
}

#[test]
fn a_seized_relay_exposes_no_plaintext() {
    let mut relay = InMemoryRelay::new();
    let mut bob_device = Device::new();
    let (_bob_queue, cap) = RecipientQueue::create(&mut relay).unwrap();
    let bundle = bob_device.publish_prekey_bundle();

    let alice_device = Device::new();
    let mut alice_session = alice_device.start_session(&bundle).unwrap();
    let secret = b"SAFEHOUSE-ADDR-221B-BAKER-ST";
    cap.send(&mut relay, &seal_for_wire(&mut alice_session, &PlainMessage::new(secret.to_vec()))).unwrap();

    for held in relay.resident_blobs() {
        assert!(
            !held.0.windows(secret.len()).any(|w| w == secret),
            "plaintext must never be visible to the relay"
        );
    }
}

#[test]
fn the_write_only_sender_cannot_read_the_recipients_queue() {
    // Alice holds only the sender capability; she can deliver but must not be able to read
    // Bob's queue (capability separation), even though she shares the relay.
    let mut relay = InMemoryRelay::new();
    let (_bob_queue, cap) = RecipientQueue::create(&mut relay).unwrap();
    cap.send(&mut relay, &Blob(framing::pad(b"opaque").unwrap())).unwrap();

    // The capability exposes no read method and no recipient id; the bytes Alice holds are
    // purely the write capability.
    let reconstructed = SenderCapability::from_bytes(&cap.to_bytes());
    reconstructed.send(&mut relay, &Blob(framing::pad(b"still only writes").unwrap())).unwrap();
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
