//! Messaging — 1:1 and group end-to-end encryption (req `7.3`). **STUB**.
//!
//! 1:1 uses libsignal's Double Ratchet (forward secrecy + post-compromise security);
//! groups use OpenMLS (RFC 9420). Messages disappear by default. This module defines the
//! traits the transport and UI layers code against; concrete sessions land later and wrap
//! the audited upstream libraries — we never roll our own ratchet.

use crate::trust::ContactId;

/// A locally-generated, non-networkable message handle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MessageId(pub [u8; 16]);

/// A cleartext message as seen only inside the device.
#[derive(Clone, Debug)]
pub struct PlainMessage {
    pub body: Vec<u8>,
    /// Disappearing-message lifetime. `None` means use the conversation default (which is
    /// itself a finite default — disappearing is on by default, req `7.3`).
    pub ttl_secs: Option<u32>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MessagingError {
    NotImplemented,
}

/// A forward-secret 1:1 session (libsignal Double Ratchet). **STUB**.
pub trait OneToOneSession {
    fn encrypt(&mut self, msg: &PlainMessage) -> Result<Vec<u8>, MessagingError>;
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<PlainMessage, MessagingError>;
}

/// A group session (OpenMLS / RFC 9420). Membership changes produce Commit/Welcome
/// messages and rotate keys (post-compromise security). **STUB**.
pub trait GroupSession {
    fn add_member(&mut self, member: ContactId) -> Result<(), MessagingError>;
    fn remove_member(&mut self, member: ContactId) -> Result<(), MessagingError>;
    fn encrypt(&mut self, msg: &PlainMessage) -> Result<Vec<u8>, MessagingError>;
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<PlainMessage, MessagingError>;
}
