//! Group membership choreography over real 1:1 sessions and queues (roadmap 1.7 remainder).
//!
//! `group.rs`'s own unit tests wire members together with an in-memory `connect()` helper
//! that installs sender keys directly. This test proves the choreography a real client
//! actually needs: a [`SenderKeyDistribution`] travels **over the pairwise Olm channel**
//! ([`messaging`]), padded ([`framing`]) onto the pairwise queue ([`queue`]), and a
//! [`GroupCiphertext`] is **fanned out** the same way to every member's queue — composing the
//! already-tested primitives exactly as `docs/roadmap.md` describes for 1.7, the way
//! `end_to_end.rs` already does for 1.3/1.4/1.6.
//!
//! The initial Olm handshake between each pair is completed directly in-memory (as
//! `messaging.rs`'s own tests do) since delivering *that* over a queue is already covered by
//! `end_to_end.rs`; what's new here is everything downstream of an established contact
//! relationship: key distribution, fan-out, and — on removal — rotation plus redistribution
//! to the members who remain.

use std::collections::HashMap;

use lattice_core::framing;
use lattice_core::group::{Group, GroupCiphertext, GroupError, GroupId, SenderKeyDistribution};
use lattice_core::messaging::{Device, OneToOneSession, PlainMessage, Session};
use lattice_core::queue::{InMemoryRelay, RecipientQueue, SenderCapability};
use lattice_core::transport::Blob;
use lattice_core::trust::{ContactId, Tier};

const GID: GroupId = [7u8; 16];

fn cid(n: u8) -> ContactId {
    let mut id = [0u8; 16];
    id[0] = n;
    id
}

/// One member's live choreography state: their view of the group, a control-channel [`Session`]
/// to each other member, the capability to write to each other member's queue, and the queue
/// each other member writes to us on. Mirrors what a real client holds per contact.
struct Member {
    group: Group,
    sessions: HashMap<ContactId, Session>,
    outbound_caps: HashMap<ContactId, SenderCapability>,
    inbound_queue: HashMap<ContactId, RecipientQueue>,
}

/// Build a full mesh of `members`: every member locally admits every other (the tier-gated
/// membership decision, made per-member as in `group.rs`'s own tests), then every unordered
/// pair gets one Olm control channel and a queue in each direction.
fn setup_full_mesh(relay: &mut InMemoryRelay, members: &[ContactId]) -> HashMap<ContactId, Member> {
    let mut devices: HashMap<ContactId, Device> = members.iter().map(|&m| (m, Device::new())).collect();
    let mut result: HashMap<ContactId, Member> = members
        .iter()
        .map(|&m| {
            (
                m,
                Member {
                    group: Group::create(GID, m),
                    sessions: HashMap::new(),
                    outbound_caps: HashMap::new(),
                    inbound_queue: HashMap::new(),
                },
            )
        })
        .collect();

    for &m in members {
        for &other in members {
            if other != m {
                result.get_mut(&m).unwrap().group.add_member(other, Tier::Vouched).unwrap();
            }
        }
    }

    for i in 0..members.len() {
        for j in (i + 1)..members.len() {
            let (a, b) = (members[i], members[j]);

            let bundle = devices.get_mut(&b).unwrap().publish_prekey_bundle();
            let a_identity = devices.get(&a).unwrap().identity_key();
            let mut session_a = devices.get(&a).unwrap().start_session(&bundle).unwrap();
            let hello = session_a.encrypt(&PlainMessage::new(b"handshake".to_vec())).unwrap();
            let (mut session_b, _) = devices.get_mut(&b).unwrap().accept_session(a_identity, &hello).unwrap();
            let ack = session_b.encrypt(&PlainMessage::new(b"handshake-ack".to_vec())).unwrap();
            session_a.decrypt(&ack).unwrap();

            result.get_mut(&a).unwrap().sessions.insert(b, session_a);
            result.get_mut(&b).unwrap().sessions.insert(a, session_b);

            let (b_reads, a_writes) = RecipientQueue::create(relay).unwrap();
            result.get_mut(&b).unwrap().inbound_queue.insert(a, b_reads);
            result.get_mut(&a).unwrap().outbound_caps.insert(b, a_writes);

            let (a_reads, b_writes) = RecipientQueue::create(relay).unwrap();
            result.get_mut(&a).unwrap().inbound_queue.insert(b, a_reads);
            result.get_mut(&b).unwrap().outbound_caps.insert(a, b_writes);
        }
    }

    result
}

/// `from` distributes their current sender key to each of `recipients` over the real pairwise
/// 1:1 channel and queue, and each recipient installs it.
fn distribute_sender_key(
    relay: &mut InMemoryRelay,
    members: &mut HashMap<ContactId, Member>,
    from: ContactId,
    recipients: &[ContactId],
) {
    let skd = members.get(&from).unwrap().group.sender_key();

    for &to in recipients {
        if to == from {
            continue;
        }
        let wire = {
            let sender = members.get_mut(&from).unwrap();
            sender.sessions.get_mut(&to).unwrap().encrypt(&PlainMessage::new(skd.to_bytes())).unwrap()
        };
        {
            let sender = members.get(&from).unwrap();
            let cap = sender.outbound_caps.get(&to).unwrap();
            cap.send(relay, &Blob(framing::pad(&wire).unwrap())).unwrap();
        }

        let blob = {
            let receiver = members.get(&to).unwrap();
            let queue = receiver.inbound_queue.get(&from).unwrap();
            let mut blobs = queue.receive(relay).unwrap();
            queue.ack(relay).unwrap();
            assert_eq!(blobs.len(), 1, "exactly one distribution delivered");
            blobs.pop().unwrap()
        };
        let plain = {
            let receiver = members.get_mut(&to).unwrap();
            let unpadded = framing::unpad(&blob.0).unwrap();
            receiver.sessions.get_mut(&from).unwrap().decrypt(&unpadded).unwrap()
        };
        let received = SenderKeyDistribution::from_bytes(&plain.body).unwrap();
        members.get_mut(&to).unwrap().group.accept_sender_key(received).unwrap();
    }
}

/// `from` encrypts one group message and fans the resulting [`GroupCiphertext`] out, padded,
/// onto each of `recipients`' queues — the delivery-side half of the choreography.
fn fan_out_group_message(
    relay: &mut InMemoryRelay,
    members: &mut HashMap<ContactId, Member>,
    from: ContactId,
    recipients: &[ContactId],
    msg: &PlainMessage,
) -> GroupCiphertext {
    let ct = members.get_mut(&from).unwrap().group.encrypt(msg);
    for &to in recipients {
        let cap = members.get(&from).unwrap().outbound_caps.get(&to).unwrap();
        cap.send(relay, &Blob(framing::pad(&ct.to_bytes()).unwrap())).unwrap();
    }
    ct
}

/// `who` drains the message `from` sent them off their queue, unpads it, and decrypts it.
fn receive_group_message(
    relay: &mut InMemoryRelay,
    members: &mut HashMap<ContactId, Member>,
    who: ContactId,
    from: ContactId,
) -> Result<PlainMessage, GroupError> {
    let blob = {
        let receiver = members.get(&who).unwrap();
        let queue = receiver.inbound_queue.get(&from).unwrap();
        let mut blobs = queue.receive(relay).unwrap();
        queue.ack(relay).unwrap();
        assert_eq!(blobs.len(), 1, "exactly one group message delivered");
        blobs.pop().unwrap()
    };
    let unpadded = framing::unpad(&blob.0).unwrap();
    let ct = GroupCiphertext::from_bytes(&unpadded).unwrap();
    members.get_mut(&who).unwrap().group.decrypt(&ct)
}

#[test]
fn group_formation_and_first_message_choreographed_over_real_channels() {
    let mut relay = InMemoryRelay::new();
    let (alice, bob, carol) = (cid(1), cid(2), cid(3));
    let roster = [alice, bob, carol];
    let mut members = setup_full_mesh(&mut relay, &roster);

    // Every member distributes their sender key to the others over their real 1:1 channel and
    // queue (not the in-memory shortcut `group.rs`'s unit tests use).
    for &m in &roster {
        distribute_sender_key(&mut relay, &mut members, m, &roster);
    }

    // Alice's message fans out over the queue to both other members.
    let msg = PlainMessage::new(b"meet at the usual place".to_vec());
    fan_out_group_message(&mut relay, &mut members, alice, &[bob, carol], &msg);

    assert_eq!(receive_group_message(&mut relay, &mut members, bob, alice).unwrap().body, msg.body);
    assert_eq!(receive_group_message(&mut relay, &mut members, carol, alice).unwrap().body, msg.body);
}

#[test]
fn removal_rotates_and_redistributes_the_key_to_the_remaining_member_over_real_channels() {
    let mut relay = InMemoryRelay::new();
    let (alice, bob, carol) = (cid(1), cid(2), cid(3));
    let roster = [alice, bob, carol];
    let mut members = setup_full_mesh(&mut relay, &roster);
    for &m in &roster {
        distribute_sender_key(&mut relay, &mut members, m, &roster);
    }

    // Baseline: Carol can read Alice's messages, delivered over the real queue.
    fan_out_group_message(
        &mut relay,
        &mut members,
        alice,
        &[bob, carol],
        &PlainMessage::new(b"still in".to_vec()),
    );
    assert_eq!(receive_group_message(&mut relay, &mut members, carol, alice).unwrap().body, b"still in");
    receive_group_message(&mut relay, &mut members, bob, alice).unwrap(); // drain Bob's copy too

    // Alice removes Carol: this rotates her outbound ratchet locally, and the new key is
    // redistributed only to the remaining member, over the real Alice<->Bob channel.
    members.get_mut(&alice).unwrap().group.remove_member(&carol).unwrap();
    distribute_sender_key(&mut relay, &mut members, alice, &[bob]);

    // Alice's next message is fanned out only to Bob — Carol is never even sent it.
    let ct = fan_out_group_message(
        &mut relay,
        &mut members,
        alice,
        &[bob],
        &PlainMessage::new(b"carol is gone".to_vec()),
    );

    assert_eq!(receive_group_message(&mut relay, &mut members, bob, alice).unwrap().body, b"carol is gone");

    // Belt-and-braces: even if Carol *had* received the ciphertext, her stale sender key for
    // Alice cannot open post-rotation traffic (the crypto property underlying the removal).
    assert_eq!(
        members.get_mut(&carol).unwrap().group.decrypt(&ct).unwrap_err(),
        GroupError::Decrypt,
        "Carol's stale sender key for Alice cannot open post-rotation traffic"
    );
}
