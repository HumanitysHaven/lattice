//! Trust graph persistence and listing (Phase 1.2/1.6, `7.2`).
//!
//! Same stateless, bytes-in/bytes-out shape as [`crate::api::identity`]: every call
//! reconstructs a [`TrustGraph`] from sealed bytes the caller already has, mutates it, and
//! returns the newly-sealed bytes for the caller to persist — reusing
//! [`lattice_core::persistence`]'s existing `snapshot`/`restore`/`seal_graph`/`open_graph`,
//! the same pattern `identity::seal_identity`/`open_identity` already established for
//! identities. Nothing here holds a `TrustGraph` in memory between calls; the invite
//! completion flow ([`crate::api::invite`]) reuses [`load_graph`]/[`save_graph`] directly
//! since adding a contact from a redeemed invite is still just "load, mutate, save."

use lattice_core::at_rest::KdfParams;
use lattice_core::persistence;
use lattice_core::trust::{ContactId, Tier, TrustGraph, TrustParams};

use crate::api::hex;

/// What a contacts screen needs to show for one contact.
#[derive(Debug, Clone)]
pub struct ContactSummary {
    /// The contact's local, non-networkable handle, as lowercase hex — compare this against
    /// what the contact sees on their own "signed in" screen to confirm you added the right
    /// person.
    pub fingerprint_hex: String,
    pub tier: String,
}

pub(crate) fn contact_id_from_hex(s: &str) -> Result<ContactId, String> {
    let bytes = hex::decode(s)?;
    bytes.try_into().map_err(|_| "a fingerprint is 16 bytes (32 hex characters)".to_string())
}

fn tier_label(tier: Tier) -> String {
    match tier {
        Tier::Invited => "Invited".to_string(),
        Tier::Vouched => "Vouched".to_string(),
        Tier::Trusted => "Trusted".to_string(),
        Tier::Core => "Core".to_string(),
    }
}

pub(crate) fn summarize_contacts(graph: &TrustGraph) -> Vec<ContactSummary> {
    let mut contacts: Vec<ContactSummary> = graph
        .iter_contacts()
        .map(|c| ContactSummary { fingerprint_hex: hex::encode(&c.id), tier: tier_label(c.tier) })
        .collect();
    contacts.sort_by(|a, b| a.fingerprint_hex.cmp(&b.fingerprint_hex));
    contacts
}

/// Open a previously-sealed trust graph and bring cached tiers up to date against `now`
/// (mirroring [`persistence::restore`]'s own advice to call
/// [`TrustGraph::recompute_all`](lattice_core::trust::TrustGraph::recompute_all) after a
/// restore).
pub(crate) fn load_graph(sealed: &[u8], passphrase: &str, now: i64) -> Result<TrustGraph, String> {
    let rows = persistence::open_graph(passphrase.as_bytes(), sealed).map_err(|err| format!("{err:?}"))?;
    let mut graph = persistence::restore(&rows, TrustParams::default()).map_err(|err| format!("{err:?}"))?;
    graph.recompute_all(now);
    Ok(graph)
}

/// Snapshot and seal a trust graph for storage.
pub(crate) fn save_graph(graph: &TrustGraph, passphrase: &str) -> Result<Vec<u8>, String> {
    let rows = persistence::snapshot(graph);
    persistence::seal_graph(passphrase.as_bytes(), &rows, KdfParams::recommended())
        .map_err(|err| format!("{err:?}"))
}

/// List contacts from a previously-sealed trust graph. `sealed` is `None` for a device with
/// no contacts yet (no invites completed).
#[flutter_rust_bridge::frb(sync)]
pub fn list_contacts(
    sealed: Option<Vec<u8>>,
    passphrase: String,
    now: i64,
) -> Result<Vec<ContactSummary>, String> {
    match sealed {
        None => Ok(Vec::new()),
        Some(bytes) => Ok(summarize_contacts(&load_graph(&bytes, &passphrase, now)?)),
    }
}
