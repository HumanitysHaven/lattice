//! Identity & key material (req `7.1`).
//!
//! A user is a set of on-device keys, never an account; no PII is collected. This module
//! implements the **Ed25519 signing identity** and **BIP39 24-word recovery** — the
//! safety-critical, dependency-light core of `7.1`. The libsignal Double Ratchet identity
//! key and per-community OpenMLS credentials layer on in the messaging milestones
//! (`docs/roadmap.md` 1.4/1.7) and reuse the same on-device seed.
//!
//! No home-grown cryptography (req `7.3`): keys are Ed25519 via the audited
//! `ed25519-dalek` crate, recovery encoding is BIP39 via the `bip39` crate, and secret
//! material is zeroized on drop and never printed.

use core::fmt;

use bip39::Mnemonic;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey as DalekVerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::trust::ContactId;

/// Length of the identity seed: 32 bytes — simultaneously the Ed25519 secret-seed size and
/// the entropy behind a 24-word BIP39 phrase.
const SEED_LEN: usize = 32;

/// Ed25519 verifying (public) key used to authenticate signed vouches/attestations.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VerifyingKey(pub [u8; 32]);

impl VerifyingKey {
    /// Verify a detached 64-byte signature over `msg`. Returns `false` on any malformed
    /// key/signature or mismatch — never panics. Uses strict verification (rejects
    /// non-canonical encodings and small-order keys).
    pub fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(vk) = DalekVerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        vk.verify_strict(msg, &Signature::from_bytes(signature)).is_ok()
    }
}

/// A BIP39 recovery phrase. User-held, offline only — never escrowed (req `7.1`). The
/// phrase is zeroized from memory on drop and redacted from debug output.
pub struct RecoveryPhrase(Zeroizing<String>);

impl RecoveryPhrase {
    /// The phrase as a single space-separated string, for display so the user can write it
    /// down. Treat as highly sensitive.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The individual words, in order.
    pub fn words(&self) -> Vec<&str> {
        self.0.split_whitespace().collect()
    }
}

impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryPhrase(<redacted>)")
    }
}

/// The user's own identity, held only on-device. The secret signing key is zeroized on
/// drop and never exposed or printed.
pub struct Identity {
    local_id: ContactId,
    signing_key: SigningKey,
    nickname: String,
    created_at: i64,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("local_id", &self.local_id)
            .field("nickname", &self.nickname)
            .field("created_at", &self.created_at)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// The operating-system CSPRNG failed to provide entropy.
    Rng,
    /// The supplied recovery phrase is not a valid 24-word BIP39 mnemonic.
    InvalidPhrase,
}

impl Identity {
    /// Generate a fresh identity from operating-system randomness.
    pub fn generate(nickname: &str) -> Result<Self, IdentityError> {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        getrandom::getrandom(seed.as_mut_slice()).map_err(|_| IdentityError::Rng)?;
        Ok(Self::from_seed(&seed, nickname))
    }

    /// Deterministically restore an identity from its recovery phrase. The same phrase
    /// always yields the same keys and `local_id` (req `7.1`); only the local `nickname`
    /// and `created_at` are set anew.
    pub fn from_recovery(phrase: &RecoveryPhrase, nickname: &str) -> Result<Self, IdentityError> {
        let mnemonic = Mnemonic::parse(phrase.as_str()).map_err(|_| IdentityError::InvalidPhrase)?;
        let (entropy, len) = mnemonic.to_entropy_array();
        let seed: [u8; SEED_LEN] =
            entropy.get(..len).and_then(|e| e.try_into().ok()).ok_or(IdentityError::InvalidPhrase)?;
        let seed = Zeroizing::new(seed);
        Ok(Self::from_seed(&seed, nickname))
    }

    /// Export the recovery phrase for the user to store offline.
    pub fn recovery_phrase(&self) -> RecoveryPhrase {
        let seed = Zeroizing::new(self.signing_key.to_bytes());
        // 32 bytes is always valid BIP39 entropy (→ exactly 24 words), so this cannot fail.
        let mnemonic = Mnemonic::from_entropy(seed.as_slice()).expect("32 bytes is valid entropy");
        RecoveryPhrase(Zeroizing::new(mnemonic.to_string()))
    }

    fn from_seed(seed: &[u8; SEED_LEN], nickname: &str) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let local_id = local_id_from_verifying_key(signing_key.verifying_key().as_bytes());
        Self { local_id, signing_key, nickname: nickname.to_string(), created_at: now_unix_seconds() }
    }

    /// The local, non-networkable handle for this identity (derived from the public key).
    pub fn local_id(&self) -> ContactId {
        self.local_id
    }

    /// The Ed25519 verifying (public) key others use to check this identity's signatures.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.signing_key.verifying_key().to_bytes())
    }

    pub fn nickname(&self) -> &str {
        &self.nickname
    }

    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    /// Sign a message (e.g. a serialized vouch payload) with the Ed25519 signing key.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg).to_bytes()
    }
}

/// Derive a stable, non-networkable local handle from a verifying key. Domain-separated so
/// it can never collide with a hash used elsewhere; truncated to the 16-byte `ContactId`.
fn local_id_from_verifying_key(vk_bytes: &[u8; 32]) -> ContactId {
    let mut hasher = Sha256::new();
    hasher.update(b"lattice/local-id/v1");
    hasher.update(vk_bytes);
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

fn now_unix_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_round_trips_to_the_same_identity() {
        let id = Identity::generate("alice").unwrap();
        let phrase = id.recovery_phrase();
        assert_eq!(phrase.words().len(), 24, "256-bit entropy must encode to 24 words");

        let restored = Identity::from_recovery(&phrase, "alice-on-new-device").unwrap();
        assert_eq!(restored.local_id(), id.local_id());
        assert_eq!(restored.verifying_key(), id.verifying_key());
        // A restored identity can produce signatures the original key verifies.
        let msg = b"after recovery";
        assert!(id.verifying_key().verify(msg, &restored.sign(msg)));
    }

    #[test]
    fn distinct_identities_differ() {
        let a = Identity::generate("a").unwrap();
        let b = Identity::generate("b").unwrap();
        assert_ne!(a.local_id(), b.local_id());
        assert_ne!(a.verifying_key(), b.verifying_key());
    }

    #[test]
    fn signatures_verify_and_reject_tampering() {
        let id = Identity::generate("signer").unwrap();
        let vk = id.verifying_key();
        let msg = b"subject||weight=3||ts=1700000000||nonce=abcd";
        let sig = id.sign(msg);
        assert!(vk.verify(msg, &sig));
        assert!(!vk.verify(b"subject||weight=2||ts=1700000000||nonce=abcd", &sig), "tampered msg");

        let mut bad = sig;
        bad[0] ^= 0xff;
        assert!(!vk.verify(msg, &bad), "tampered signature");
    }

    #[test]
    fn a_signature_does_not_verify_under_a_different_key() {
        let signer = Identity::generate("s").unwrap();
        let other = Identity::generate("o").unwrap();
        let msg = b"hello";
        let sig = signer.sign(msg);
        assert!(signer.verifying_key().verify(msg, &sig));
        assert!(!other.verifying_key().verify(msg, &sig));
    }

    #[test]
    fn invalid_recovery_phrase_is_rejected() {
        let phrase = RecoveryPhrase(Zeroizing::new("not a valid mnemonic at all".to_string()));
        assert_eq!(Identity::from_recovery(&phrase, "x").unwrap_err(), IdentityError::InvalidPhrase);
    }

    #[test]
    fn local_id_is_derived_from_the_verifying_key() {
        let id = Identity::generate("x").unwrap();
        assert_eq!(id.local_id(), local_id_from_verifying_key(&id.verifying_key().0));
    }

    #[test]
    fn debug_redacts_secret_material() {
        let id = Identity::generate("nick").unwrap();
        let rendered = format!("{id:?}");
        assert!(rendered.contains("redacted"), "secret key must not appear in Debug");
        assert!(rendered.contains("nick"), "non-secret fields are fine to show");
        assert_eq!(format!("{:?}", id.recovery_phrase()), "RecoveryPhrase(<redacted>)");
    }
}
