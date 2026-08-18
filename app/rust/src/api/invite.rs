//! Invite issuance and completion (Phase 1.5 core, `7.2`, `S11`).
//!
//! Text-only for this pass — no QR/camera yet, an invite is just an opaque hex string the
//! issuer shares with the invitee over any channel they trust, matching the project's
//! "invitation only, no discovery" model (`docs/threat-model.md` §6).
//!
//! **Only the issuer acts here.** [`lattice_core::invite::InviteBook::redeem`] is called by
//! whoever *issued* the token, against their own bookkeeping — that's how single-use and
//! expiry are enforced authoritatively (`docs/roadmap.md` 1.5). In the full system the
//! invitee's redemption request reaches the issuer over the anonymous-queue transport
//! (1.3/1.4), which isn't wired into this UI yet; for now, completing an invite means the
//! issuer manually enters the invitee's fingerprint (visible on the invitee's own "signed
//! in" screen) once they've confirmed out-of-band that the invitee has the token.
//!
//! [`InviteBookHandle`] is this crate's first genuinely *stateful* FFI object — everywhere
//! else ([`crate::api::identity`], [`crate::api::contacts`]) is stateless bytes-in/bytes-out.
//! That's not a style change: `InviteBook` has no serialization support in `core` yet (its
//! own docs mark persistence as deferred — losing outstanding, unredeemed invites on an app
//! restart is an acceptable trade-off for this slice, unlike an identity or a contact list).
//! Keeping one live `InviteBook` for the app's session is the smallest thing that preserves
//! its real security property (single-use enforcement) without inventing new `core`
//! persistence that wasn't asked for.

use std::sync::Mutex;

use lattice_core::invite::{InviteBook, InviteToken};
use lattice_core::trust::{TrustGraph, TrustParams};

use crate::api::contacts::{self, ContactSummary};
use crate::api::hex;

/// The result of successfully completing an invite: the newly-sealed trust graph to persist,
/// and the up-to-date contact list to display.
#[derive(Debug, Clone)]
pub struct CompletedInvite {
    pub sealed_graph: Vec<u8>,
    pub contacts: Vec<ContactSummary>,
}

/// One issuer's outstanding invites for the lifetime of the app session (see module docs for
/// why this — and only this — is stateful).
pub struct InviteBookHandle {
    inner: Mutex<InviteBook>,
}

impl InviteBookHandle {
    #[flutter_rust_bridge::frb(sync)]
    pub fn new() -> Self {
        Self { inner: Mutex::new(InviteBook::new()) }
    }

    /// Issue a fresh invite valid for `ttl_secs` from `now`, returned as hex text to share.
    #[flutter_rust_bridge::frb(sync)]
    pub fn issue(&self, ttl_secs: i64, now: i64) -> Result<String, String> {
        let mut book = self.inner.lock().map_err(|_| "invite book lock poisoned".to_string())?;
        let token = book.issue(ttl_secs, now).map_err(|err| format!("{err:?}"))?;
        Ok(hex::encode(&token.to_bytes()))
    }

    /// Complete a pending invite: validate `token_text` against this issuer's own
    /// bookkeeping (rejecting it if already used, expired, or unknown — same as
    /// [`InviteBook::redeem`](lattice_core::invite::InviteBook::redeem)), then add the
    /// invitee as a Tier-0 contact under `contact_fingerprint_hex` in the trust graph
    /// (`existing_sealed_graph`, or a fresh one if this is the first contact).
    #[flutter_rust_bridge::frb(sync)]
    pub fn complete(
        &self,
        token_text: String,
        contact_fingerprint_hex: String,
        existing_sealed_graph: Option<Vec<u8>>,
        passphrase: String,
        now: i64,
    ) -> Result<CompletedInvite, String> {
        let token_bytes = hex::decode(&token_text)?;
        let token = InviteToken::from_bytes(&token_bytes).map_err(|err| format!("{err:?}"))?;
        let contact_id = contacts::contact_id_from_hex(&contact_fingerprint_hex)?;

        let grant = {
            let mut book = self.inner.lock().map_err(|_| "invite book lock poisoned".to_string())?;
            book.redeem(&token, now).map_err(|err| format!("{err:?}"))?
        };

        let mut graph = match existing_sealed_graph {
            Some(bytes) => contacts::load_graph(&bytes, &passphrase, now)?,
            None => TrustGraph::new(TrustParams::default()),
        };
        graph.upsert_contact(grant.into_contact(contact_id));
        graph.recompute_all(now);

        Ok(CompletedInvite {
            sealed_graph: contacts::save_graph(&graph, &passphrase)?,
            contacts: contacts::summarize_contacts(&graph),
        })
    }
}
