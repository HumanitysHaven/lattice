//! Invitation onboarding (req `7.2`, scenario `S11`) — the *only* way a new contact enters.
//!
//! Growth is by personal, out-of-band invitation (in-person QR or a one-time link). There
//! is deliberately **no discovery of strangers** — the single biggest entrapment vector,
//! excluded by design (threat model §6). An invite token is **single-use**, **short-lived**,
//! and **carries no identity**: only an ephemeral secret and an expiry. Expired, used,
//! revoked, or unknown tokens are inert (`S11`).
//!
//! This module models the token lifecycle purely (no network, no handshake): the issuer
//! keeps an [`InviteBook`] of outstanding invites and validates redemptions against it,
//! authoritatively (a tampered token cannot extend its own TTL — the stored record wins).
//! The anonymous-queue handshake that actually carries a redemption and binds the new
//! contact's keys lands with the transport/messaging milestones (1.3/1.4); a successful
//! redemption here yields a [`Grant`] that becomes the invitee's **Tier-0** contact.
//!
//! Invites always onboard at `Tier::Invited`. Higher tiers are earned only through
//! accountable vouching (see [`crate::vouching`]), never granted by an invite — an invite
//! must not become a shortcut around the web of trust.

use core::fmt;
use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::trust::{AddedVia, Contact, ContactId};

const TOKEN_VERSION: u8 = 1;
const SECRET_LEN: usize = 32;
/// Wire length of an encoded token: version byte + secret + big-endian expiry.
const ENCODED_LEN: usize = 1 + SECRET_LEN + 8;

/// Why an invite operation failed.
#[derive(Debug, PartialEq, Eq)]
pub enum InviteError {
    /// The OS CSPRNG failed to provide entropy.
    Rng,
    /// A non-positive time-to-live was requested.
    BadTtl,
    /// The token is unknown to this issuer (never issued here, revoked, or purged).
    Unknown,
    /// The token has already been redeemed (single-use).
    AlreadyUsed,
    /// The token's validity window has passed.
    Expired,
    /// The encoded bytes are not a valid token.
    Malformed,
}

/// A one-time invite token, shared out-of-band (QR / link). It contains **no identity** —
/// only an ephemeral secret and an advisory expiry — and is zeroized-friendly: the secret
/// is private and never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct InviteToken {
    secret: [u8; SECRET_LEN],
    expires_at: i64,
}

impl InviteToken {
    /// Advisory expiry carried for the invitee's UI. Redemption is validated against the
    /// issuer's authoritative record, not this field.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Encode for transport in a QR code or one-time link.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENCODED_LEN);
        out.push(TOKEN_VERSION);
        out.extend_from_slice(&self.secret);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out
    }

    /// Decode a token received out-of-band. Rejects wrong length or unknown version.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InviteError> {
        if bytes.len() != ENCODED_LEN || bytes[0] != TOKEN_VERSION {
            return Err(InviteError::Malformed);
        }
        let mut secret = [0u8; SECRET_LEN];
        secret.copy_from_slice(&bytes[1..1 + SECRET_LEN]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&bytes[1 + SECRET_LEN..]);
        Ok(Self { secret, expires_at: i64::from_be_bytes(ts) })
    }

    /// A domain-separated commitment to the secret. The issuer stores this (not the raw
    /// secret) and looks invites up by it on redemption.
    fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"lattice/invite/v1");
        hasher.update(self.secret);
        hasher.finalize().into()
    }
}

impl fmt::Debug for InviteToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteToken")
            .field("secret", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Proof that an invite was validly redeemed. Convert it into the invitee's Tier-0 contact
/// once the invitee's local handle is known (derived from their identity at handshake).
#[must_use]
#[derive(Debug)]
pub struct Grant {
    _seal: (),
}

impl Grant {
    /// Build the Tier-0 (`AddedVia::Invite`) contact for the redeemed invitee.
    pub fn into_contact(self, invitee: ContactId) -> Contact {
        Contact::new(invitee, AddedVia::Invite)
    }
}

struct PendingInvite {
    expires_at: i64,
    used: bool,
}

/// The issuer's set of outstanding invites. Authoritative for expiry and single-use.
///
/// In-memory for now; it will be persisted via the encrypted store in a later milestone so
/// outstanding invites survive a restart (and so a seized device reveals only commitments,
/// not raw secrets).
#[derive(Default)]
pub struct InviteBook {
    pending: HashMap<[u8; 32], PendingInvite>,
}

impl InviteBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of invites still redeemable (issued, unused, and not yet purged).
    pub fn outstanding(&self) -> usize {
        self.pending.values().filter(|p| !p.used).count()
    }

    /// Issue a fresh single-use token valid for `ttl_secs` from `now`. The caller should
    /// keep TTLs short (threat model favours brief windows) and share the token only over
    /// a trusted out-of-band channel.
    pub fn issue(&mut self, ttl_secs: i64, now: i64) -> Result<InviteToken, InviteError> {
        if ttl_secs <= 0 {
            return Err(InviteError::BadTtl);
        }
        let mut secret = [0u8; SECRET_LEN];
        getrandom::getrandom(&mut secret).map_err(|_| InviteError::Rng)?;
        let token = InviteToken { secret, expires_at: now.saturating_add(ttl_secs) };
        self.pending.insert(token.commitment(), PendingInvite { expires_at: token.expires_at, used: false });
        Ok(token)
    }

    /// Validate and consume a token. On success it is marked used (so a second redemption
    /// fails) and a [`Grant`] is returned. Expiry is checked against the stored record.
    pub fn redeem(&mut self, token: &InviteToken, now: i64) -> Result<Grant, InviteError> {
        let pending = self.pending.get_mut(&token.commitment()).ok_or(InviteError::Unknown)?;
        if pending.used {
            return Err(InviteError::AlreadyUsed);
        }
        if now > pending.expires_at {
            return Err(InviteError::Expired);
        }
        pending.used = true;
        Ok(Grant { _seal: () })
    }

    /// Cancel an outstanding invite before it is redeemed. Returns whether it existed.
    pub fn revoke(&mut self, token: &InviteToken) -> bool {
        self.pending.remove(&token.commitment()).is_some()
    }

    /// Drop every invite whose validity window has passed. Returns how many were removed.
    pub fn purge_expired(&mut self, now: i64) -> usize {
        let before = self.pending.len();
        self.pending.retain(|_, p| now <= p.expires_at);
        before - self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::trust::{Tier, TrustGraph, TrustParams};

    const NOW: i64 = 1_900_000_000;
    const HOUR: i64 = 3_600;

    #[test]
    fn issue_then_redeem_succeeds_exactly_once() {
        let mut book = InviteBook::new();
        let token = book.issue(HOUR, NOW).unwrap();
        assert_eq!(book.outstanding(), 1);

        assert!(book.redeem(&token, NOW).is_ok());
        assert_eq!(book.outstanding(), 0, "a redeemed invite is no longer outstanding");
        assert_eq!(book.redeem(&token, NOW).unwrap_err(), InviteError::AlreadyUsed);
    }

    #[test]
    fn expired_token_is_inert() {
        let mut book = InviteBook::new();
        let token = book.issue(10, NOW).unwrap();
        assert_eq!(book.redeem(&token, NOW + 11).unwrap_err(), InviteError::Expired);
    }

    #[test]
    fn revoked_token_is_inert() {
        let mut book = InviteBook::new();
        let token = book.issue(HOUR, NOW).unwrap();
        assert!(book.revoke(&token));
        assert!(!book.revoke(&token), "revoking twice reports it was already gone");
        assert_eq!(book.redeem(&token, NOW).unwrap_err(), InviteError::Unknown);
    }

    #[test]
    fn a_token_unknown_to_the_issuer_is_inert() {
        let issuer_a = InviteBook::new();
        let mut issuer_b = InviteBook::new();
        // A token minted by one issuer means nothing to another.
        let mut a = issuer_a;
        let token = a.issue(HOUR, NOW).unwrap();
        assert_eq!(issuer_b.redeem(&token, NOW).unwrap_err(), InviteError::Unknown);
    }

    #[test]
    fn non_positive_ttl_is_rejected() {
        let mut book = InviteBook::new();
        assert_eq!(book.issue(0, NOW).unwrap_err(), InviteError::BadTtl);
        assert_eq!(book.issue(-5, NOW).unwrap_err(), InviteError::BadTtl);
    }

    #[test]
    fn issued_tokens_are_unique() {
        let mut book = InviteBook::new();
        let t1 = book.issue(HOUR, NOW).unwrap();
        let t2 = book.issue(HOUR, NOW).unwrap();
        assert_ne!(t1.to_bytes(), t2.to_bytes(), "secrets must be random per invite");
    }

    #[test]
    fn token_round_trips_through_bytes_and_carries_no_identity() {
        let mut book = InviteBook::new();
        let token = book.issue(HOUR, NOW).unwrap();
        let bytes = token.to_bytes();
        assert_eq!(bytes.len(), ENCODED_LEN, "no room for any identity beyond secret+expiry");
        assert_eq!(bytes[0], TOKEN_VERSION);

        let decoded = InviteToken::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, token);
        // A decoded token still redeems against the issuer.
        assert!(book.redeem(&decoded, NOW).is_ok());
    }

    #[test]
    fn malformed_bytes_are_rejected() {
        assert_eq!(InviteToken::from_bytes(&[]).unwrap_err(), InviteError::Malformed);
        assert_eq!(InviteToken::from_bytes(&[0u8; ENCODED_LEN]).unwrap_err(), InviteError::Malformed);
        let mut book = InviteBook::new();
        let mut bytes = book.issue(HOUR, NOW).unwrap().to_bytes();
        bytes.push(0); // wrong length
        assert_eq!(InviteToken::from_bytes(&bytes).unwrap_err(), InviteError::Malformed);
    }

    #[test]
    fn purge_removes_only_expired_invites() {
        let mut book = InviteBook::new();
        let _short = book.issue(10, NOW).unwrap();
        let long = book.issue(HOUR, NOW).unwrap();
        assert_eq!(book.purge_expired(NOW + 100), 1, "only the short-lived invite expired");
        assert!(book.redeem(&long, NOW + 100).is_ok());
    }

    #[test]
    fn debug_redacts_the_secret() {
        let mut book = InviteBook::new();
        let token = book.issue(HOUR, NOW).unwrap();
        assert!(format!("{token:?}").contains("redacted"));
    }

    #[test]
    fn redemption_onboards_the_invitee_at_tier0() {
        let mut book = InviteBook::new();
        let token = book.issue(HOUR, NOW).unwrap();
        let grant = book.redeem(&token, NOW).unwrap();

        // The invitee's local handle comes from their identity (known at handshake).
        let invitee = Identity::generate("newcomer").unwrap();
        let contact = grant.into_contact(invitee.verifying_key().local_id());
        assert_eq!(contact.added_via, AddedVia::Invite);

        let mut g = TrustGraph::new(TrustParams::default());
        g.upsert_contact(contact);
        let id = invitee.verifying_key().local_id();
        assert_eq!(g.recompute_tier(&id, NOW), Tier::Invited);

        let caps = g.contact(&id).unwrap().tier.capabilities();
        assert!(caps.direct_message, "Tier 0 can DM their inviter");
        assert!(!caps.group_chat, "Tier 0 cannot yet join groups");
    }
}
