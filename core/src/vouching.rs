//! Signed attestations: the bridge between [`crate::identity`] and the pure
//! [`crate::trust`] engine (spec §5.2/§5.3, req `7.2`).
//!
//! Over the wire, a vouch or a burn is an authenticated object signed by the issuer's
//! Ed25519 key and referencing peers by **public key**. This module signs and verifies
//! those objects, and — on success — produces the plain, crypto-free [`crate::trust`]
//! values the engine consumes. The trust engine itself never touches signatures or keys;
//! verification happens here, at the ingestion boundary, so a forged or tampered
//! attestation can never reach scoring.
//!
//! Signatures are over a **canonical, domain-separated** byte encoding. The domain tag
//! makes a signature valid only for its own purpose — a vouch signature can never be
//! replayed as a burn (or vice-versa), even if the field bytes were to coincide.

use crate::identity::{Identity, VerifyingKey};
use crate::trust::{BurnSignal, Vouch};

const VOUCH_DOMAIN: &[u8] = b"lattice/vouch/v1";
const BURN_DOMAIN: &[u8] = b"lattice/burn/v1";

/// Why an attestation failed verification.
#[derive(Debug, PartialEq, Eq)]
pub enum VouchError {
    /// Vouch weight outside the valid 1..=3 range.
    BadWeight,
    /// Signature did not verify under the claimed issuer key.
    BadSignature,
}

/// The signed content of a vouch (spec §5.2):
/// `Sign_voucher( subject_pubkey || weight || timestamp || nonce )`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VouchPayload {
    /// The contact being vouched for, identified by their public key.
    pub subject: VerifyingKey,
    /// Voucher-asserted confidence, 1..=3.
    pub weight: u8,
    /// Unix seconds.
    pub created_at: i64,
    /// Per-vouch random nonce so otherwise-identical vouches are distinct objects.
    pub nonce: [u8; 16],
}

impl VouchPayload {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(VOUCH_DOMAIN.len() + 32 + 1 + 8 + 16);
        out.extend_from_slice(VOUCH_DOMAIN);
        out.extend_from_slice(&self.subject.0);
        out.push(self.weight);
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }
}

/// A vouch authenticated by its issuer's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedVouch {
    /// The issuer (voucher), identified by their public key.
    pub voucher: VerifyingKey,
    pub payload: VouchPayload,
    pub signature: [u8; 64],
}

impl SignedVouch {
    /// Issue a vouch for `subject` from `identity`. Weight is clamped to 1..=3 before
    /// signing so the signed value is always valid.
    pub fn issue(
        identity: &Identity,
        subject: &VerifyingKey,
        weight: u8,
        created_at: i64,
        nonce: [u8; 16],
    ) -> Self {
        let payload =
            VouchPayload { subject: subject.clone(), weight: weight.clamp(1, 3), created_at, nonce };
        let signature = identity.sign(&payload.canonical_bytes());
        Self { voucher: identity.verifying_key(), payload, signature }
    }

    /// Verify the signature and weight, and on success produce the engine-level
    /// [`Vouch`] (peers resolved from public keys to local handles). The returned vouch is
    /// never `revoked` — revocation is a separate, later local action.
    pub fn verify(&self) -> Result<Vouch, VouchError> {
        if !(1..=3).contains(&self.payload.weight) {
            return Err(VouchError::BadWeight);
        }
        if !self.voucher.verify(&self.payload.canonical_bytes(), &self.signature) {
            return Err(VouchError::BadSignature);
        }
        Ok(Vouch {
            subject: self.payload.subject.local_id(),
            voucher: self.voucher.local_id(),
            weight: self.payload.weight,
            created_at: self.payload.created_at,
            revoked: false,
        })
    }
}

/// The signed content of a burn signal (spec §5.3): a coarse, non-identifying
/// "this contact is compromised" assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnPayload {
    /// The contact flagged as compromised, identified by their public key.
    pub subject: VerifyingKey,
    /// Coarse, non-identifying reason code (carried for provenance; the pure trust engine
    /// does not interpret it).
    pub reason_code: u8,
    /// Unix seconds.
    pub created_at: i64,
    /// Per-signal random nonce.
    pub nonce: [u8; 16],
}

impl BurnPayload {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BURN_DOMAIN.len() + 32 + 1 + 8 + 16);
        out.extend_from_slice(BURN_DOMAIN);
        out.extend_from_slice(&self.subject.0);
        out.push(self.reason_code);
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }
}

/// A burn signal authenticated by its origin's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBurn {
    /// The issuer (origin) of the signal, identified by their public key.
    pub origin: VerifyingKey,
    pub payload: BurnPayload,
    pub signature: [u8; 64],
}

impl SignedBurn {
    /// Issue a burn signal for `subject` from `identity`.
    pub fn issue(
        identity: &Identity,
        subject: &VerifyingKey,
        reason_code: u8,
        created_at: i64,
        nonce: [u8; 16],
    ) -> Self {
        let payload = BurnPayload { subject: subject.clone(), reason_code, created_at, nonce };
        let signature = identity.sign(&payload.canonical_bytes());
        Self { origin: identity.verifying_key(), payload, signature }
    }

    /// Verify the signature and on success produce the engine-level [`BurnSignal`]. The
    /// coarse `reason_code` is intentionally dropped — the pure engine does not use it.
    pub fn verify(&self) -> Result<BurnSignal, VouchError> {
        if !self.origin.verify(&self.payload.canonical_bytes(), &self.signature) {
            return Err(VouchError::BadSignature);
        }
        Ok(BurnSignal {
            subject: self.payload.subject.local_id(),
            origin: self.origin.local_id(),
            created_at: self.payload.created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::{AddedVia, Contact, Tier, TrustGraph, TrustParams};

    const NOW: i64 = 1_900_000_000;

    fn nonce(n: u8) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[0] = n;
        a
    }

    #[test]
    fn a_valid_signed_vouch_verifies() {
        let voucher = Identity::generate("voucher").unwrap();
        let subject = Identity::generate("subject").unwrap();
        let signed = SignedVouch::issue(&voucher, &subject.verifying_key(), 3, NOW, nonce(1));

        let vouch = signed.verify().expect("valid vouch");
        assert_eq!(vouch.voucher, voucher.verifying_key().local_id());
        assert_eq!(vouch.subject, subject.verifying_key().local_id());
        assert_eq!(vouch.weight, 3);
        assert!(!vouch.revoked);
    }

    #[test]
    fn a_tampered_vouch_is_rejected() {
        let voucher = Identity::generate("voucher").unwrap();
        let subject = Identity::generate("subject").unwrap();
        let mut signed = SignedVouch::issue(&voucher, &subject.verifying_key(), 2, NOW, nonce(1));

        // Tamper with the signed field: verification must fail.
        signed.payload.weight = 3;
        assert_eq!(signed.verify().unwrap_err(), VouchError::BadSignature);
    }

    #[test]
    fn a_vouch_does_not_verify_under_a_forged_issuer() {
        let voucher = Identity::generate("voucher").unwrap();
        let attacker = Identity::generate("attacker").unwrap();
        let subject = Identity::generate("subject").unwrap();
        let mut signed = SignedVouch::issue(&voucher, &subject.verifying_key(), 3, NOW, nonce(1));

        // Claim a different issuer while keeping the original signature.
        signed.voucher = attacker.verifying_key();
        assert_eq!(signed.verify().unwrap_err(), VouchError::BadSignature);
    }

    #[test]
    fn end_to_end_signed_vouch_drives_a_tier_promotion() {
        // Two anchored vouchers each issue a signed vouch for a subject; once verified and
        // fed to the engine, the subject reaches Tier 2 (Trusted).
        let a = Identity::generate("anchor-a").unwrap();
        let b = Identity::generate("anchor-b").unwrap();
        let subject = Identity::generate("subject").unwrap();

        let mut g = TrustGraph::new(TrustParams::default());
        g.upsert_contact(
            Contact::new(a.verifying_key().local_id(), AddedVia::Invite).with_manual_floor(Tier::Core),
        );
        g.upsert_contact(
            Contact::new(b.verifying_key().local_id(), AddedVia::Invite).with_manual_floor(Tier::Core),
        );
        g.upsert_contact(Contact::new(subject.verifying_key().local_id(), AddedVia::VouchedIntro));

        for (voucher, n) in [(&a, 1u8), (&b, 2u8)] {
            let signed = SignedVouch::issue(voucher, &subject.verifying_key(), 3, NOW, nonce(n));
            g.add_vouch(signed.verify().expect("valid vouch"));
        }
        g.recompute_all(NOW);
        assert_eq!(g.contact(&subject.verifying_key().local_id()).unwrap().tier, Tier::Trusted);
    }

    #[test]
    fn end_to_end_signed_burn_strips_trust() {
        let a = Identity::generate("anchor-a").unwrap();
        let subject = Identity::generate("subject").unwrap();

        let mut g = TrustGraph::new(TrustParams::default());
        g.upsert_contact(
            Contact::new(a.verifying_key().local_id(), AddedVia::Invite).with_manual_floor(Tier::Core),
        );
        let subject_id = subject.verifying_key().local_id();
        g.upsert_contact(Contact::new(subject_id, AddedVia::VouchedIntro));

        let vouch = SignedVouch::issue(&a, &subject.verifying_key(), 3, NOW, nonce(1));
        g.add_vouch(vouch.verify().unwrap());
        g.recompute_all(NOW);
        assert!(g.contact(&subject_id).unwrap().tier >= Tier::Vouched);

        // The same anchor now signs a burn for the subject.
        let burn = SignedBurn::issue(&a, &subject.verifying_key(), 1, NOW, nonce(2));
        g.add_burn(burn.verify().unwrap());
        g.recompute_all(NOW);
        assert_eq!(g.contact(&subject_id).unwrap().tier, Tier::Invited);
    }

    #[test]
    fn a_tampered_burn_is_rejected() {
        let origin = Identity::generate("origin").unwrap();
        let subject = Identity::generate("subject").unwrap();
        let mut signed = SignedBurn::issue(&origin, &subject.verifying_key(), 1, NOW, nonce(1));
        signed.payload.created_at = NOW + 1;
        assert_eq!(signed.verify().unwrap_err(), VouchError::BadSignature);
    }
}
