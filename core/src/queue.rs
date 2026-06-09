//! Anonymous simplex-queue transport protocol (req `7.4`, threat `S5`).
//!
//! Milestone 1.3. Modelled on SimpleX's **SMP**: messages travel through **one-directional
//! ("simplex") queues** held on **untrusted relays**. This module is the pure, auditable
//! protocol kernel — the command codec, the per-queue key model, and a reference relay that
//! enforces the rules — so the security-relevant logic can be tested with zero network. The
//! real networked relay client (these same commands shipped over Tor) is a thin edge that
//! implements the [`Relay`] trait; nothing here opens a socket.
//!
//! ## Why this resists a hostile relay
//!
//! - **No identities.** A queue is named by two independent random ids — a *recipient id*
//!   (used privately by the receiver) and a *sender id* (handed to exactly one contact). No
//!   user identifier, key fingerprint, or contact handle ever reaches the relay.
//! - **Capability separation.** The receiver holds a per-queue recipient key; the one contact
//!   holds a separate sender key. Reads ([`RecipientQueue::receive`]/`ack`/`delete`) require
//!   the recipient key; writes ([`SenderCapability::send`]) require the sender key. A contact
//!   who can *write* to you therefore cannot *read* your queue, and never even learns its
//!   recipient id.
//! - **Authenticated commands.** Every command is Ed25519-signed over a domain-separated,
//!   canonical encoding and verified by the relay against the key registered for that queue.
//!   A forged or replayed-cross-queue command is rejected.
//! - **Per-contact queues.** Each contact gets its own queue, so compromise or enumeration of
//!   one reveals nothing about the others.
//!
//! What this kernel deliberately does *not* provide on its own is network-level
//! unlinkability of the two queue ids or of a user's several queues; that comes from running
//! the [`Relay`] edge over **Tor with per-queue connections** (and SMP's 2-hop routing), which
//! is the remaining networked work. The relay still sees only opaque, fixed-size blobs
//! ([`crate::framing`]) and never their contents.
//!
//! The per-queue keys are ephemeral and unrelated to the user's [`crate::identity`] signing
//! key, so queues can never be correlated back to a stable identity.

use std::collections::HashMap;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::transport::Blob;

/// Domain tag mixed into every signed command so a queue signature can never be replayed as
/// some other lattice signature (or vice versa).
const DOMAIN: &[u8] = b"lattice/smp/v1";
const ID_LEN: usize = 16;

/// A random, identity-free queue address.
type QueueId = [u8; ID_LEN];

/// Why a queue operation failed.
#[derive(Debug, PartialEq, Eq)]
pub enum QueueError {
    /// The command bytes could not be decoded.
    Malformed,
    /// The command's signature did not verify under the key registered for the queue.
    Unauthorized,
    /// No queue exists for the given recipient or sender id.
    NoSuchQueue,
    /// A queue with the given recipient or sender id already exists.
    QueueExists,
    /// The OS CSPRNG failed to provide entropy.
    Rng,
}

/// A relay command. Carries only random ids, public keys, and opaque blobs — never identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Command {
    /// Provision a new queue. Signed by the recipient key.
    Create { recipient_id: QueueId, sender_id: QueueId, recipient_vk: [u8; 32], sender_vk: [u8; 32] },
    /// Append a blob to the queue addressed by `sender_id`. Signed by the sender key.
    Send { sender_id: QueueId, blob: Vec<u8> },
    /// Read the queue's pending blobs. Signed by the recipient key.
    Receive { recipient_id: QueueId },
    /// Clear delivered blobs. Signed by the recipient key.
    Ack { recipient_id: QueueId },
    /// Tear down the queue. Signed by the recipient key.
    Delete { recipient_id: QueueId },
}

impl Command {
    /// The exact bytes that are signed/verified: domain tag plus the canonical encoding.
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&postcard::to_allocvec(self).expect("command serializes"));
        out
    }
}

/// A command together with its detached signature, as sent to the relay.
#[derive(Serialize, Deserialize)]
struct SignedCommand {
    command: Command,
    signature: Vec<u8>,
}

/// The relay's reply to a command.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// The command succeeded with no payload.
    Ok,
    /// The pending blobs on a queue (reply to [`Command::Receive`]).
    Messages(Vec<Blob>),
}

/// A relay: it accepts a signed command (already serialized, exactly as it would arrive over
/// the wire) and returns a [`Response`]. The reference [`InMemoryRelay`] enforces the protocol
/// for tests and local development; a networked implementation ships these bytes over Tor.
pub trait Relay {
    fn submit(&mut self, signed_command: &[u8]) -> Result<Response, QueueError>;
}

/// A queue's server-side record. The relay only ever holds public keys and opaque blobs.
struct Record {
    recipient_vk: [u8; 32],
    sender_vk: [u8; 32],
    mailbox: Vec<Blob>,
}

/// A reference, in-memory [`Relay`] that faithfully enforces authorization and capability
/// separation. It is the untrusted party in the threat model: it sees only random ids, public
/// keys, and opaque blobs, and cannot read message contents.
#[derive(Default)]
pub struct InMemoryRelay {
    by_recipient: HashMap<QueueId, Record>,
    sender_to_recipient: HashMap<QueueId, QueueId>,
}

impl InMemoryRelay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of live queues (diagnostics/tests).
    pub fn queue_count(&self) -> usize {
        self.by_recipient.len()
    }

    /// Every blob the relay currently holds across all queues — what a relay seizure would
    /// expose (only opaque, fixed-size blobs). For diagnostics and tests.
    pub fn resident_blobs(&self) -> impl Iterator<Item = &Blob> {
        self.by_recipient.values().flat_map(|r| r.mailbox.iter())
    }
}

impl Relay for InMemoryRelay {
    fn submit(&mut self, signed_command: &[u8]) -> Result<Response, QueueError> {
        let SignedCommand { command, signature } =
            postcard::from_bytes(signed_command).map_err(|_| QueueError::Malformed)?;

        match &command {
            Command::Create { recipient_id, sender_id, recipient_vk, sender_vk } => {
                authorize(recipient_vk, &command, &signature)?;
                if self.by_recipient.contains_key(recipient_id)
                    || self.sender_to_recipient.contains_key(sender_id)
                {
                    return Err(QueueError::QueueExists);
                }
                self.by_recipient.insert(
                    *recipient_id,
                    Record { recipient_vk: *recipient_vk, sender_vk: *sender_vk, mailbox: Vec::new() },
                );
                self.sender_to_recipient.insert(*sender_id, *recipient_id);
                Ok(Response::Ok)
            }
            Command::Send { sender_id, blob } => {
                let recipient_id = *self.sender_to_recipient.get(sender_id).ok_or(QueueError::NoSuchQueue)?;
                let record = self.by_recipient.get_mut(&recipient_id).ok_or(QueueError::NoSuchQueue)?;
                authorize(&record.sender_vk, &command, &signature)?;
                record.mailbox.push(Blob(blob.clone()));
                Ok(Response::Ok)
            }
            Command::Receive { recipient_id } => {
                let record = self.by_recipient.get(recipient_id).ok_or(QueueError::NoSuchQueue)?;
                authorize(&record.recipient_vk, &command, &signature)?;
                Ok(Response::Messages(record.mailbox.clone()))
            }
            Command::Ack { recipient_id } => {
                let record = self.by_recipient.get_mut(recipient_id).ok_or(QueueError::NoSuchQueue)?;
                authorize(&record.recipient_vk, &command, &signature)?;
                record.mailbox.clear();
                Ok(Response::Ok)
            }
            Command::Delete { recipient_id } => {
                let record = self.by_recipient.get(recipient_id).ok_or(QueueError::NoSuchQueue)?;
                authorize(&record.recipient_vk, &command, &signature)?;
                self.by_recipient.remove(recipient_id);
                self.sender_to_recipient.retain(|_, rid| rid != recipient_id);
                Ok(Response::Ok)
            }
        }
    }
}

/// Verify `signature` over `command` under the Ed25519 public key `vk_bytes`. Any malformed
/// key/signature or mismatch yields [`QueueError::Unauthorized`] — never a panic.
fn authorize(vk_bytes: &[u8; 32], command: &Command, signature: &[u8]) -> Result<(), QueueError> {
    let vk = VerifyingKey::from_bytes(vk_bytes).map_err(|_| QueueError::Unauthorized)?;
    let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| QueueError::Unauthorized)?;
    let signature = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(&command.signing_bytes(), &signature).map_err(|_| QueueError::Unauthorized)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], QueueError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|_| QueueError::Rng)?;
    Ok(buf)
}

fn random_key() -> Result<SigningKey, QueueError> {
    Ok(SigningKey::from_bytes(&random_bytes::<32>()?))
}

fn sign(key: &SigningKey, command: &Command) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let signature = key.sign(&command.signing_bytes());
    let signed = SignedCommand { command: command.clone(), signature: signature.to_bytes().to_vec() };
    postcard::to_allocvec(&signed).expect("signed command serializes")
}

/// The receiver's private handle to a queue: the recipient id and the key that authorizes
/// reads. The signing key is zeroized on drop (ed25519-dalek `zeroize` feature).
pub struct RecipientQueue {
    recipient_id: QueueId,
    recipient_key: SigningKey,
}

impl RecipientQueue {
    /// Provision a new simplex queue on `relay`, returning the private recipient handle and the
    /// [`SenderCapability`] to hand to exactly one contact (e.g. bundled with the invite).
    pub fn create(relay: &mut impl Relay) -> Result<(Self, SenderCapability), QueueError> {
        let recipient_key = random_key()?;
        let sender_key = random_key()?;
        let recipient_id = random_bytes::<ID_LEN>()?;
        let sender_id = random_bytes::<ID_LEN>()?;

        let command = Command::Create {
            recipient_id,
            sender_id,
            recipient_vk: recipient_key.verifying_key().to_bytes(),
            sender_vk: sender_key.verifying_key().to_bytes(),
        };
        relay.submit(&sign(&recipient_key, &command))?;

        Ok((Self { recipient_id, recipient_key }, SenderCapability { sender_id, sender_key }))
    }

    /// Read (without clearing) the blobs waiting on this queue.
    pub fn receive(&self, relay: &mut impl Relay) -> Result<Vec<Blob>, QueueError> {
        match relay
            .submit(&sign(&self.recipient_key, &Command::Receive { recipient_id: self.recipient_id }))?
        {
            Response::Messages(blobs) => Ok(blobs),
            Response::Ok => Err(QueueError::Malformed),
        }
    }

    /// Clear all delivered blobs from this queue.
    pub fn ack(&self, relay: &mut impl Relay) -> Result<(), QueueError> {
        relay.submit(&sign(&self.recipient_key, &Command::Ack { recipient_id: self.recipient_id }))?;
        Ok(())
    }

    /// Tear the queue down on the relay.
    pub fn delete(&self, relay: &mut impl Relay) -> Result<(), QueueError> {
        relay.submit(&sign(&self.recipient_key, &Command::Delete { recipient_id: self.recipient_id }))?;
        Ok(())
    }
}

/// The write-only capability for a single contact: the sender id plus the key that authorizes
/// writes. It conveys no ability to read the queue and does not reveal the recipient id.
pub struct SenderCapability {
    sender_id: QueueId,
    sender_key: SigningKey,
}

impl SenderCapability {
    /// Append `blob` to the queue. Authorized by the sender key.
    pub fn send(&self, relay: &mut impl Relay, blob: &Blob) -> Result<(), QueueError> {
        let command = Command::Send { sender_id: self.sender_id, blob: blob.0.clone() };
        relay.submit(&sign(&self.sender_key, &command))?;
        Ok(())
    }

    /// Encode the capability (`sender_id || sender_seed`, 48 bytes) to hand to the contact
    /// out-of-band alongside the invite. Highly sensitive: it grants write access.
    pub fn to_bytes(&self) -> [u8; ID_LEN + 32] {
        let mut out = [0u8; ID_LEN + 32];
        out[..ID_LEN].copy_from_slice(&self.sender_id);
        out[ID_LEN..].copy_from_slice(&self.sender_key.to_bytes());
        out
    }

    /// Decode a capability received out-of-band.
    pub fn from_bytes(bytes: &[u8; ID_LEN + 32]) -> Self {
        let mut sender_id = [0u8; ID_LEN];
        sender_id.copy_from_slice(&bytes[..ID_LEN]);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[ID_LEN..]);
        Self { sender_id, sender_key: SigningKey::from_bytes(&seed) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(tag: u8) -> Blob {
        Blob(vec![tag; 64])
    }

    #[test]
    fn create_send_receive_round_trips() {
        let mut relay = InMemoryRelay::new();
        let (queue, cap) = RecipientQueue::create(&mut relay).unwrap();

        cap.send(&mut relay, &blob(0xAA)).unwrap();
        assert_eq!(queue.receive(&mut relay).unwrap(), vec![blob(0xAA)]);
    }

    #[test]
    fn the_sender_capability_cannot_read_the_queue() {
        // The contact only ever learns the sender id, never the recipient id, so it cannot
        // even name the queue for a read; using the sender id as a recipient id finds nothing.
        let mut relay = InMemoryRelay::new();
        let (_queue, cap) = RecipientQueue::create(&mut relay).unwrap();
        cap.send(&mut relay, &blob(1)).unwrap();

        let forged_read =
            RecipientQueue { recipient_id: cap.sender_id, recipient_key: cap.sender_key.clone() };
        assert_eq!(forged_read.receive(&mut relay).unwrap_err(), QueueError::NoSuchQueue);
    }

    #[test]
    fn a_read_with_the_wrong_key_is_rejected() {
        let mut relay = InMemoryRelay::new();
        let (queue, _cap) = RecipientQueue::create(&mut relay).unwrap();

        // Same recipient id, attacker-chosen key: the relay rejects the bad signature.
        let imposter =
            RecipientQueue { recipient_id: queue.recipient_id, recipient_key: random_key().unwrap() };
        assert_eq!(imposter.receive(&mut relay).unwrap_err(), QueueError::Unauthorized);
    }

    #[test]
    fn a_write_with_the_wrong_key_is_rejected() {
        let mut relay = InMemoryRelay::new();
        let (_queue, cap) = RecipientQueue::create(&mut relay).unwrap();

        let imposter = SenderCapability { sender_id: cap.sender_id, sender_key: random_key().unwrap() };
        assert_eq!(imposter.send(&mut relay, &blob(2)).unwrap_err(), QueueError::Unauthorized);
    }

    #[test]
    fn ack_clears_the_mailbox() {
        let mut relay = InMemoryRelay::new();
        let (queue, cap) = RecipientQueue::create(&mut relay).unwrap();
        cap.send(&mut relay, &blob(3)).unwrap();
        cap.send(&mut relay, &blob(4)).unwrap();

        assert_eq!(queue.receive(&mut relay).unwrap().len(), 2);
        queue.ack(&mut relay).unwrap();
        assert!(queue.receive(&mut relay).unwrap().is_empty());
    }

    #[test]
    fn delete_removes_the_queue() {
        let mut relay = InMemoryRelay::new();
        let (queue, cap) = RecipientQueue::create(&mut relay).unwrap();
        queue.delete(&mut relay).unwrap();

        assert_eq!(queue.receive(&mut relay).unwrap_err(), QueueError::NoSuchQueue);
        assert_eq!(cap.send(&mut relay, &blob(5)).unwrap_err(), QueueError::NoSuchQueue);
        assert_eq!(relay.queue_count(), 0);
    }

    #[test]
    fn distinct_queues_are_isolated() {
        let mut relay = InMemoryRelay::new();
        let (q1, c1) = RecipientQueue::create(&mut relay).unwrap();
        let (q2, c2) = RecipientQueue::create(&mut relay).unwrap();

        c1.send(&mut relay, &blob(0x11)).unwrap();
        c2.send(&mut relay, &blob(0x22)).unwrap();

        assert_eq!(q1.receive(&mut relay).unwrap(), vec![blob(0x11)]);
        assert_eq!(q2.receive(&mut relay).unwrap(), vec![blob(0x22)]);
        assert_eq!(relay.queue_count(), 2);
    }

    #[test]
    fn queue_ids_and_keys_carry_no_shared_structure() {
        let mut relay = InMemoryRelay::new();
        let (q1, c1) = RecipientQueue::create(&mut relay).unwrap();
        let (q2, c2) = RecipientQueue::create(&mut relay).unwrap();

        // Two queues from the same user share nothing the relay could correlate.
        assert_ne!(q1.recipient_id, q2.recipient_id);
        assert_ne!(c1.sender_id, c2.sender_id);
        assert_ne!(q1.recipient_id, c1.sender_id, "recipient and sender ids are independent");
    }

    #[test]
    fn a_sender_capability_round_trips_through_bytes() {
        let mut relay = InMemoryRelay::new();
        let (_queue, cap) = RecipientQueue::create(&mut relay).unwrap();
        let restored = SenderCapability::from_bytes(&cap.to_bytes());
        assert_eq!(restored.to_bytes(), cap.to_bytes());
        // The restored capability still works.
        restored.send(&mut relay, &blob(9)).unwrap();
    }

    #[test]
    fn unknown_queue_and_malformed_bytes_are_handled() {
        let mut relay = InMemoryRelay::new();
        assert_eq!(relay.submit(b"not a command").unwrap_err(), QueueError::Malformed);

        // A well-formed Send to a never-created queue.
        let cap = SenderCapability { sender_id: [9u8; ID_LEN], sender_key: random_key().unwrap() };
        assert_eq!(cap.send(&mut relay, &blob(0)).unwrap_err(), QueueError::NoSuchQueue);
    }

    #[test]
    fn a_creation_id_collision_is_rejected() {
        // Two creates that collide on an id must not silently overwrite a live queue.
        let mut relay = InMemoryRelay::new();
        let key = random_key().unwrap();
        let command = Command::Create {
            recipient_id: [1u8; ID_LEN],
            sender_id: [2u8; ID_LEN],
            recipient_vk: key.verifying_key().to_bytes(),
            sender_vk: key.verifying_key().to_bytes(),
        };
        relay.submit(&sign(&key, &command)).unwrap();
        assert_eq!(relay.submit(&sign(&key, &command)).unwrap_err(), QueueError::QueueExists);
    }
}
