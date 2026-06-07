//! Identity & key material (req `7.1`). **STUB** — types and intent only.
//!
//! A user is a set of on-device keys, never an account. No PII is ever collected.
//! Real key generation (Ed25519 for signing vouches; libsignal identity keys for 1:1
//! sessions; per-community OpenMLS credentials) lands in a later milestone. The types
//! here pin down the shape so the rest of the core can be written against them.

use crate::trust::ContactId;

/// Ed25519 verifying (public) key used to authenticate signed vouches/attestations.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VerifyingKey(pub [u8; 32]);

/// A BIP39-style recovery phrase. User-held, offline only — never escrowed (req `7.1`).
#[derive(Clone)]
pub struct RecoveryPhrase(pub Vec<String>);

/// The user's own identity, held only on-device.
#[derive(Clone)]
pub struct Identity {
    /// Local, non-networkable handle for self.
    pub local_id: ContactId,
    pub verifying_key: VerifyingKey,
    /// User-chosen display name; not unique, never published to the network.
    pub nickname: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// Functionality is scaffolded but not yet implemented.
    NotImplemented,
}

impl Identity {
    /// Generate a fresh identity from secure randomness.
    pub fn generate(_nickname: &str) -> Result<Self, IdentityError> {
        // TODO: CSPRNG seed -> Ed25519 keypair + libsignal identity; derive local_id.
        Err(IdentityError::NotImplemented)
    }

    /// Deterministically restore an identity from its recovery phrase.
    pub fn from_recovery(_phrase: &RecoveryPhrase, _nickname: &str) -> Result<Self, IdentityError> {
        // TODO: phrase -> seed -> same keys as `generate` produced originally.
        Err(IdentityError::NotImplemented)
    }

    /// Export the recovery phrase for the user to store offline.
    pub fn recovery_phrase(&self) -> Result<RecoveryPhrase, IdentityError> {
        // TODO: encode the seed as a word list.
        Err(IdentityError::NotImplemented)
    }
}
