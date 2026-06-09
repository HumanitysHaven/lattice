//! 1:1 end-to-end messaging via the Double Ratchet (req `7.3`).
//!
//! Confidentiality, **forward secrecy**, and **post-compromise security** for direct messages
//! come from the audited [Olm](https://gitlab.matrix.org/matrix-org/olm) Double Ratchet, as
//! implemented by the pure-Rust [`vodozemac`] crate. We never roll our own ratchet
//! (req `7.3`): this module is a thin, safety-preserving wrapper that adapts Olm to lattice's
//! identity-free, metadata-resistant model and carries lattice's disappearing-message
//! semantics inside the encrypted payload.
//!
//! ## Why Olm/vodozemac (deviation from the spec's libsignal)
//!
//! The spec named libsignal. In practice libsignal is not consumable as a hermetic Rust
//! dependency — it is git-only (not on crates.io), AGPL, and pulls in BoringSSL and forked
//! crates — which conflicts with this crate's pure, reproducible, cross-platform build.
//! `vodozemac` implements the **same Double Ratchet** (Olm), is pure Rust on crates.io, and
//! has been independently audited (Least Authority, no significant findings). It also provides
//! Megolm, which the group-chat milestone (1.7) will build on. See `docs/technical-spec.md`.
//!
//! ## Shape of the API
//!
//! A [`Device`] owns the long-lived Olm [`Account`]. To start talking, the responder publishes
//! a [`PreKeyBundle`] (identity key + a one-time key) out-of-band — in lattice, alongside the
//! invite handshake — and the initiator calls [`Device::start_session`]. The first ciphertext
//! is a *pre-key* message; the responder feeds it to [`Device::accept_session`] to derive the
//! matching [`Session`]. Thereafter both sides use [`Session::encrypt`]/[`Session::decrypt`]
//! (the [`OneToOneSession`] trait). Each [`Session::encrypt`] advances the ratchet.
//!
//! On the wire a message is `message_type(1) || olm_ciphertext`. That ciphertext is already
//! confidential, so the transport only needs to **pad it to a fixed size**
//! ([`crate::framing::pad`]) before handing it to a relay — there is no second key to manage
//! here. Replay/ordering beyond what Olm provides, and message expiry enforcement, belong to
//! the storage/UI layers; this module only guarantees the cryptographic channel and preserves
//! the [`PlainMessage::ttl_secs`] end-to-end.

use vodozemac::olm::{Account, OlmMessage, SessionConfig};
use vodozemac::Curve25519PublicKey;

/// A locally-generated, non-networkable message handle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MessageId(pub [u8; 16]);

/// A cleartext message as seen only inside the device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlainMessage {
    pub body: Vec<u8>,
    /// Disappearing-message lifetime. `None` means use the conversation default (which is
    /// itself a finite default — disappearing is on by default, req `7.3`). Carried inside the
    /// encrypted payload so a relay never learns it.
    pub ttl_secs: Option<u32>,
}

impl PlainMessage {
    /// Convenience constructor for a message that uses the conversation's default lifetime.
    pub fn new(body: impl Into<Vec<u8>>) -> Self {
        Self { body: body.into(), ttl_secs: None }
    }

    /// Encode to the bytes that are handed to the ratchet: `has_ttl(1) || ttl(4) || body`.
    /// Shared with [`crate::group`] so 1:1 and group messages carry the TTL identically.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + self.body.len());
        out.push(u8::from(self.ttl_secs.is_some()));
        out.extend_from_slice(&self.ttl_secs.unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, MessagingError> {
        if bytes.len() < 5 {
            return Err(MessagingError::Malformed);
        }
        let ttl_secs = match bytes[0] {
            0 => None,
            1 => Some(u32::from_be_bytes(bytes[1..5].try_into().unwrap())),
            _ => return Err(MessagingError::Malformed),
        };
        Ok(Self { body: bytes[5..].to_vec(), ttl_secs })
    }
}

/// Why a messaging operation failed.
#[derive(Debug, PartialEq, Eq)]
pub enum MessagingError {
    /// A session could not be established from the provided keys/pre-key message.
    SessionCreation,
    /// The ratchet failed to encrypt the message.
    Encrypt,
    /// Authenticated decryption failed: wrong session, replay, or tampering.
    Decrypt,
    /// A wire message or pre-key bundle was structurally invalid.
    Malformed,
    /// The first message of a session was expected to be a pre-key message but was not.
    NotAPreKeyMessage,
    /// Functionality not yet implemented (group sessions land in milestone 1.7).
    NotImplemented,
}

/// A responder's published key material: the long-term Curve25519 identity key plus one
/// single-use one-time key. Shared out-of-band (with the invite); carries no lattice identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreKeyBundle {
    identity_key: [u8; 32],
    one_time_key: [u8; 32],
}

impl PreKeyBundle {
    /// Raw 64-byte encoding (`identity_key || one_time_key`) for transport in the handshake.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.identity_key);
        out[32..].copy_from_slice(&self.one_time_key);
        out
    }

    /// Decode a bundle received out-of-band.
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut identity_key = [0u8; 32];
        let mut one_time_key = [0u8; 32];
        identity_key.copy_from_slice(&bytes[..32]);
        one_time_key.copy_from_slice(&bytes[32..]);
        Self { identity_key, one_time_key }
    }
}

/// A device's long-lived Olm account: the root of its 1:1 messaging key material.
///
/// The account is *separate* from the [`crate::identity::Identity`] signing key for now; a
/// later milestone can derive both from the same on-device seed (see `docs/roadmap.md` 1.4).
pub struct Device {
    account: Account,
}

impl Default for Device {
    fn default() -> Self {
        Self::new()
    }
}

impl Device {
    /// Create a device with fresh Olm identity keys.
    pub fn new() -> Self {
        Self { account: Account::new() }
    }

    /// The device's public Curve25519 identity key (needed by a peer to accept our pre-key
    /// message).
    pub fn identity_key(&self) -> [u8; 32] {
        self.account.curve25519_key().to_bytes()
    }

    /// Generate and publish a one-time key, returning a [`PreKeyBundle`] a peer can use to
    /// start a session with us. Each bundle's one-time key is single-use.
    pub fn publish_prekey_bundle(&mut self) -> PreKeyBundle {
        self.account.generate_one_time_keys(1);
        let one_time_key = self
            .account
            .one_time_keys()
            .values()
            .next()
            .copied()
            .expect("we just generated a one-time key")
            .to_bytes();
        let identity_key = self.account.curve25519_key().to_bytes();
        self.account.mark_keys_as_published();
        PreKeyBundle { identity_key, one_time_key }
    }

    /// Initiator side: start an outbound session to a peer described by their [`PreKeyBundle`].
    /// The first message produced by the returned session will be a pre-key message.
    pub fn start_session(&self, peer: &PreKeyBundle) -> Result<Session, MessagingError> {
        let identity_key = Curve25519PublicKey::from_bytes(peer.identity_key);
        let one_time_key = Curve25519PublicKey::from_bytes(peer.one_time_key);
        let session = self
            .account
            .create_outbound_session(SessionConfig::version_1(), identity_key, one_time_key)
            .map_err(|_| MessagingError::SessionCreation)?;
        Ok(Session { inner: session })
    }

    /// Responder side: accept the first (pre-key) wire message from `sender_identity`, deriving
    /// the matching session and returning it together with that first decrypted message.
    pub fn accept_session(
        &mut self,
        sender_identity: [u8; 32],
        first_wire: &[u8],
    ) -> Result<(Session, PlainMessage), MessagingError> {
        let message = decode_wire(first_wire)?;
        let OlmMessage::PreKey(pre_key) = message else {
            return Err(MessagingError::NotAPreKeyMessage);
        };
        let their_identity = Curve25519PublicKey::from_bytes(sender_identity);
        let result = self
            .account
            .create_inbound_session(SessionConfig::version_1(), their_identity, &pre_key)
            .map_err(|_| MessagingError::SessionCreation)?;
        let plaintext = PlainMessage::decode(&result.plaintext)?;
        Ok((Session { inner: result.session }, plaintext))
    }
}

/// One end of an established Double Ratchet channel. Each [`encrypt`](Session::encrypt)
/// advances the sending ratchet (forward secrecy); receiving the peer's reply advances the
/// receiving ratchet (post-compromise security).
pub struct Session {
    inner: vodozemac::olm::Session,
}

impl Session {
    /// The shared session identifier (equal on both ends once established). Useful for tying a
    /// session to a conversation locally; never sent to a relay.
    pub fn session_id(&self) -> String {
        self.inner.session_id()
    }
}

impl OneToOneSession for Session {
    fn encrypt(&mut self, msg: &PlainMessage) -> Result<Vec<u8>, MessagingError> {
        let olm = self.inner.encrypt(msg.encode()).map_err(|_| MessagingError::Encrypt)?;
        Ok(encode_wire(&olm))
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<PlainMessage, MessagingError> {
        let message = decode_wire(ciphertext)?;
        let plaintext = self.inner.decrypt(&message).map_err(|_| MessagingError::Decrypt)?;
        PlainMessage::decode(&plaintext)
    }
}

/// Encode an Olm message for the wire: `message_type(1) || ciphertext`.
fn encode_wire(message: &OlmMessage) -> Vec<u8> {
    let (message_type, ciphertext) = message.to_parts();
    let mut out = Vec::with_capacity(1 + ciphertext.len());
    out.push(message_type as u8);
    out.extend_from_slice(&ciphertext);
    out
}

fn decode_wire(bytes: &[u8]) -> Result<OlmMessage, MessagingError> {
    if bytes.is_empty() {
        return Err(MessagingError::Malformed);
    }
    OlmMessage::from_parts(bytes[0] as usize, &bytes[1..]).map_err(|_| MessagingError::Malformed)
}

/// A forward-secret 1:1 session. Implemented by [`Session`] over the Olm Double Ratchet.
pub trait OneToOneSession {
    /// Encrypt and advance the ratchet, returning the wire bytes to pad and send.
    fn encrypt(&mut self, msg: &PlainMessage) -> Result<Vec<u8>, MessagingError>;
    /// Decrypt a wire message received from the peer.
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<PlainMessage, MessagingError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Establish a fully-bidirectional pair of sessions: Alice starts, Bob accepts the pre-key
    /// message, then replies so Alice's receiving ratchet is initialised too.
    fn established_pair() -> (Session, Session) {
        let alice = Device::new();
        let mut bob = Device::new();
        let bundle = bob.publish_prekey_bundle();

        let mut alice_session = alice.start_session(&bundle).unwrap();
        let hello = alice_session.encrypt(&PlainMessage::new(b"hello".to_vec())).unwrap();
        let (mut bob_session, first) = bob.accept_session(alice.identity_key(), &hello).unwrap();
        assert_eq!(first.body, b"hello");

        // Bob replies so Alice can complete the handshake on her side.
        let reply = bob_session.encrypt(&PlainMessage::new(b"hi".to_vec())).unwrap();
        let got = alice_session.decrypt(&reply).unwrap();
        assert_eq!(got.body, b"hi");

        (alice_session, bob_session)
    }

    #[test]
    fn handshake_establishes_a_shared_session() {
        let alice = Device::new();
        let mut bob = Device::new();
        let bundle = bob.publish_prekey_bundle();

        let mut alice_session = alice.start_session(&bundle).unwrap();
        let wire = alice_session.encrypt(&PlainMessage::new(b"first contact".to_vec())).unwrap();
        let (bob_session, first) = bob.accept_session(alice.identity_key(), &wire).unwrap();

        assert_eq!(first.body, b"first contact");
        assert_eq!(alice_session.session_id(), bob_session.session_id());
    }

    #[test]
    fn messages_round_trip_in_both_directions() {
        let (mut alice, mut bob) = established_pair();

        let wire = alice.encrypt(&PlainMessage::new(b"meet at noon".to_vec())).unwrap();
        assert_eq!(bob.decrypt(&wire).unwrap().body, b"meet at noon");

        let wire = bob.encrypt(&PlainMessage::new(b"understood".to_vec())).unwrap();
        assert_eq!(alice.decrypt(&wire).unwrap().body, b"understood");
    }

    #[test]
    fn the_ratchet_advances_so_each_message_differs() {
        let (mut alice, mut bob) = established_pair();
        let a = alice.encrypt(&PlainMessage::new(b"same body".to_vec())).unwrap();
        let b = alice.encrypt(&PlainMessage::new(b"same body".to_vec())).unwrap();
        assert_ne!(a, b, "identical plaintext must produce different ciphertext as the ratchet turns");
        // Delivered in order, both decrypt.
        assert_eq!(bob.decrypt(&a).unwrap().body, b"same body");
        assert_eq!(bob.decrypt(&b).unwrap().body, b"same body");
    }

    #[test]
    fn out_of_order_delivery_still_decrypts() {
        let (mut alice, mut bob) = established_pair();
        let m1 = alice.encrypt(&PlainMessage::new(b"one".to_vec())).unwrap();
        let m2 = alice.encrypt(&PlainMessage::new(b"two".to_vec())).unwrap();
        let m3 = alice.encrypt(&PlainMessage::new(b"three".to_vec())).unwrap();

        // Olm tolerates out-of-order within the ratchet's skipped-key window.
        assert_eq!(bob.decrypt(&m3).unwrap().body, b"three");
        assert_eq!(bob.decrypt(&m1).unwrap().body, b"one");
        assert_eq!(bob.decrypt(&m2).unwrap().body, b"two");
    }

    #[test]
    fn the_disappearing_ttl_is_preserved_end_to_end() {
        let (mut alice, mut bob) = established_pair();
        let msg = PlainMessage { body: b"burn after reading".to_vec(), ttl_secs: Some(30) };
        let wire = alice.encrypt(&msg).unwrap();
        let received = bob.decrypt(&wire).unwrap();
        assert_eq!(received, msg);
        assert_eq!(received.ttl_secs, Some(30));
    }

    #[test]
    fn a_tampered_ciphertext_is_rejected() {
        let (mut alice, mut bob) = established_pair();
        let mut wire = alice.encrypt(&PlainMessage::new(b"integrity".to_vec())).unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        assert_eq!(bob.decrypt(&wire).unwrap_err(), MessagingError::Decrypt);
    }

    #[test]
    fn a_third_party_session_cannot_decrypt() {
        let (mut alice, _bob) = established_pair();
        let wire = alice.encrypt(&PlainMessage::new(b"not for you".to_vec())).unwrap();

        // Eve sets up her own session with a fresh Bob; she must not read Alice↔Bob traffic.
        let mut eve_bob = Device::new();
        let bundle = eve_bob.publish_prekey_bundle();
        let eve = Device::new();
        let mut eve_session = eve.start_session(&bundle).unwrap();
        let intro = eve_session.encrypt(&PlainMessage::new(b"hi".to_vec())).unwrap();
        let (mut eve_bob_session, _) = eve_bob.accept_session(eve.identity_key(), &intro).unwrap();

        assert!(eve_bob_session.decrypt(&wire).is_err(), "a foreign session cannot decrypt");
    }

    #[test]
    fn a_one_time_key_is_single_use() {
        let mut bob = Device::new();
        let b1 = bob.publish_prekey_bundle();
        let b2 = bob.publish_prekey_bundle();
        assert_ne!(b1.one_time_key, b2.one_time_key, "each published bundle has a fresh one-time key");
    }

    #[test]
    fn a_prekey_bundle_round_trips_through_bytes() {
        let mut bob = Device::new();
        let bundle = bob.publish_prekey_bundle();
        let restored = PreKeyBundle::from_bytes(&bundle.to_bytes());
        assert_eq!(restored, bundle);
    }

    #[test]
    fn malformed_wire_is_rejected() {
        let (_alice, mut bob) = established_pair();
        assert_eq!(bob.decrypt(&[]).unwrap_err(), MessagingError::Malformed);
    }
}
