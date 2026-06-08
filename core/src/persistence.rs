//! Persistence mapping for the local trust store.
//!
//! This module is **storage-engine-agnostic on purpose**. It defines the SQL schema and
//! converts the in-memory trust types to and from plain *row* structs built only from
//! primitive column values, and it can snapshot/restore a whole [`TrustGraph`]. The actual
//! database (SQLCipher, encrypted at rest under an Argon2id-derived key — req `7.3`/`7.6`)
//! is wired in a later milestone; keeping this layer pure means it stays unit-testable with
//! no I/O and no native dependency, and the encryption boundary lives entirely below it.
//!
//! ## Scope vs. `docs/technical-spec.md` §4
//!
//! This layer persists exactly the state the **pure trust engine** owns and can faithfully
//! round-trip. The trust engine is deliberately minimal (no crypto, no identity, no I/O),
//! so columns from the spec's §4 schema that belong to other layers are intentionally
//! **not** stored here yet; they will be added by the modules that own them:
//!
//! | spec §4 column | status here | owner / when |
//! |----------------|-------------|--------------|
//! | `contact.pubkey_sign` | deferred | `identity` (key material) |
//! | `contact.nickname` | deferred | `identity` (local display only) |
//! | `contact.inviter_id`, `first_seen` | deferred | app/UI metadata milestone |
//! | `vouch.signature`, `nonce` | deferred | `identity`/crypto (verified on ingest) |
//! | `vouch.vouch_id` | not needed | identified by `(subject, voucher, created_at)` |
//! | `vouch.revoked_at` | stored as `revoked` (bool) | engine models revocation as a flag |
//! | `burn_signal.signature`, `reason_code` | deferred | crypto / UI |
//! | `burn_signal.signal_id` | not needed | identified by `(subject, origin, created_at)` |
//!
//! Keeping the schema in step with the engine (rather than pre-creating columns with no
//! source of truth) avoids silent data loss and keeps the encryption boundary clean.
//!
//! Column-type conventions:
//! - `ContactId` (`[u8; 16]`) ↔ `BLOB`, represented here as `Vec<u8>`.
//! - enums ↔ short `TEXT` tags.
//! - timestamps ↔ `INTEGER` (unix seconds).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::at_rest::{self, KdfParams, VaultError};
use crate::trust::{AddedVia, BurnSignal, Contact, ContactId, Status, Tier, TrustGraph, TrustParams, Vouch};

/// Data-definition SQL for the local store. Applied once to a fresh encrypted database.
pub const SCHEMA_SQL: &str = "\
CREATE TABLE IF NOT EXISTS contact (
  contact_id   BLOB PRIMARY KEY NOT NULL,
  added_via    TEXT NOT NULL,
  status       TEXT NOT NULL,
  tier         INTEGER NOT NULL,
  manual_floor INTEGER NULL
);
CREATE TABLE IF NOT EXISTS vouch (
  subject_id   BLOB NOT NULL,
  voucher_id   BLOB NOT NULL,
  weight       INTEGER NOT NULL,
  created_at   INTEGER NOT NULL,
  revoked      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (subject_id, voucher_id, created_at)
);
CREATE TABLE IF NOT EXISTS burn_signal (
  subject_id   BLOB NOT NULL,
  origin_id    BLOB NOT NULL,
  created_at   INTEGER NOT NULL,
  PRIMARY KEY (subject_id, origin_id, created_at)
);
CREATE INDEX IF NOT EXISTS idx_vouch_subject ON vouch(subject_id);
CREATE INDEX IF NOT EXISTS idx_burn_subject ON burn_signal(subject_id);
";

/// Error raised when a stored row cannot be decoded back into a domain type.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    BadContactId,
    BadEnumTag(&'static str),
    BadTier,
}

fn id_to_blob(id: &ContactId) -> Vec<u8> {
    id.to_vec()
}

fn blob_to_id(blob: &[u8]) -> Result<ContactId, DecodeError> {
    blob.try_into().map_err(|_| DecodeError::BadContactId)
}

fn added_via_tag(v: AddedVia) -> &'static str {
    match v {
        AddedVia::Invite => "invite",
        AddedVia::VouchedIntro => "vouched_intro",
    }
}

fn added_via_from(tag: &str) -> Result<AddedVia, DecodeError> {
    match tag {
        "invite" => Ok(AddedVia::Invite),
        "vouched_intro" => Ok(AddedVia::VouchedIntro),
        _ => Err(DecodeError::BadEnumTag("added_via")),
    }
}

fn status_tag(s: Status) -> &'static str {
    match s {
        Status::Active => "active",
        Status::Paused => "paused",
        Status::Burned => "burned",
    }
}

fn status_from(tag: &str) -> Result<Status, DecodeError> {
    match tag {
        "active" => Ok(Status::Active),
        "paused" => Ok(Status::Paused),
        "burned" => Ok(Status::Burned),
        _ => Err(DecodeError::BadEnumTag("status")),
    }
}

fn tier_to_int(t: Tier) -> i64 {
    t as i64
}

fn tier_from_int(n: i64) -> Result<Tier, DecodeError> {
    match n {
        0 => Ok(Tier::Invited),
        1 => Ok(Tier::Vouched),
        2 => Ok(Tier::Trusted),
        3 => Ok(Tier::Core),
        _ => Err(DecodeError::BadTier),
    }
}

/// A `contact` table row as primitive column values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactRow {
    pub contact_id: Vec<u8>,
    pub added_via: String,
    pub status: String,
    pub tier: i64,
    /// `NULL` (i.e. `None`) when the contact has no user-set trust anchor.
    pub manual_floor: Option<i64>,
}

impl ContactRow {
    pub fn from_contact(c: &Contact) -> Self {
        Self {
            contact_id: id_to_blob(&c.id),
            added_via: added_via_tag(c.added_via).to_string(),
            status: status_tag(c.status).to_string(),
            tier: tier_to_int(c.tier),
            manual_floor: c.manual_floor.map(tier_to_int),
        }
    }

    pub fn to_contact(&self) -> Result<Contact, DecodeError> {
        Ok(Contact {
            id: blob_to_id(&self.contact_id)?,
            added_via: added_via_from(&self.added_via)?,
            status: status_from(&self.status)?,
            tier: tier_from_int(self.tier)?,
            manual_floor: self.manual_floor.map(tier_from_int).transpose()?,
        })
    }
}

/// A `vouch` table row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VouchRow {
    pub subject_id: Vec<u8>,
    pub voucher_id: Vec<u8>,
    pub weight: i64,
    pub created_at: i64,
    pub revoked: i64,
}

impl VouchRow {
    pub fn from_vouch(v: &Vouch) -> Self {
        Self {
            subject_id: id_to_blob(&v.subject),
            voucher_id: id_to_blob(&v.voucher),
            weight: v.weight as i64,
            created_at: v.created_at,
            revoked: v.revoked as i64,
        }
    }

    pub fn to_vouch(&self) -> Result<Vouch, DecodeError> {
        Ok(Vouch {
            subject: blob_to_id(&self.subject_id)?,
            voucher: blob_to_id(&self.voucher_id)?,
            weight: self.weight.clamp(1, 3) as u8,
            created_at: self.created_at,
            revoked: self.revoked != 0,
        })
    }
}

/// A `burn_signal` table row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnRow {
    pub subject_id: Vec<u8>,
    pub origin_id: Vec<u8>,
    pub created_at: i64,
}

impl BurnRow {
    pub fn from_burn(b: &BurnSignal) -> Self {
        Self {
            subject_id: id_to_blob(&b.subject),
            origin_id: id_to_blob(&b.origin),
            created_at: b.created_at,
        }
    }

    pub fn to_burn(&self) -> Result<BurnSignal, DecodeError> {
        Ok(BurnSignal {
            subject: blob_to_id(&self.subject_id)?,
            origin: blob_to_id(&self.origin_id)?,
            created_at: self.created_at,
        })
    }
}

/// A complete row-level snapshot of a [`TrustGraph`] — everything the persistence layer
/// stores. Scoring parameters are *policy*, not data, so they are not part of the snapshot
/// (they are supplied at [`restore`] time).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphRows {
    pub contacts: Vec<ContactRow>,
    pub vouches: Vec<VouchRow>,
    pub burns: Vec<BurnRow>,
}

/// Convert a live [`TrustGraph`] into its row-level form, ready to be written to the store.
///
/// Rows are sorted into a deterministic order (contacts by id; vouches/burns by their
/// natural keys) so repeated snapshots of an unchanged graph are byte-for-byte identical —
/// useful for change detection and reproducible tests.
pub fn snapshot(graph: &TrustGraph) -> GraphRows {
    let mut contacts: Vec<ContactRow> = graph.iter_contacts().map(ContactRow::from_contact).collect();
    contacts.sort_by(|a, b| a.contact_id.cmp(&b.contact_id));

    let mut vouches: Vec<VouchRow> = graph.vouches().iter().map(VouchRow::from_vouch).collect();
    vouches.sort_by(|a, b| {
        (&a.subject_id, &a.voucher_id, a.created_at).cmp(&(&b.subject_id, &b.voucher_id, b.created_at))
    });

    let mut burns: Vec<BurnRow> = graph.burns().iter().map(BurnRow::from_burn).collect();
    burns.sort_by(|a, b| {
        (&a.subject_id, &a.origin_id, a.created_at).cmp(&(&b.subject_id, &b.origin_id, b.created_at))
    });

    GraphRows { contacts, vouches, burns }
}

/// Rebuild a [`TrustGraph`] from a row-level snapshot under the given scoring policy.
///
/// This restores the *stored* state only; cached tiers are loaded as-is. Call
/// [`TrustGraph::recompute_all`] afterwards if the policy may have changed since the
/// snapshot was taken. Returns a [`DecodeError`] if any row is malformed.
pub fn restore(rows: &GraphRows, params: TrustParams) -> Result<TrustGraph, DecodeError> {
    let mut graph = TrustGraph::new(params);
    for row in &rows.contacts {
        graph.upsert_contact(row.to_contact()?);
    }
    for row in &rows.vouches {
        graph.add_vouch(row.to_vouch()?);
    }
    for row in &rows.burns {
        graph.add_burn(row.to_burn()?);
    }
    Ok(graph)
}

/// Error sealing or opening the encrypted store.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The encrypted vault layer failed (wrong passphrase, tamper, malformed).
    Vault(VaultError),
    /// The decrypted bytes are not a valid serialized [`GraphRows`].
    Codec,
}

/// Serialize a snapshot and seal it under `passphrase` for storage on disk (req `7.3`).
/// The plaintext serialization is zeroized after sealing.
pub fn seal_graph(passphrase: &[u8], rows: &GraphRows, params: KdfParams) -> Result<Vec<u8>, StoreError> {
    let plaintext = Zeroizing::new(postcard::to_allocvec(rows).map_err(|_| StoreError::Codec)?);
    at_rest::seal(passphrase, &plaintext, params).map_err(StoreError::Vault)
}

/// Open and deserialize a blob produced by [`seal_graph`]. The decrypted plaintext is
/// zeroized after decoding.
pub fn open_graph(passphrase: &[u8], sealed: &[u8]) -> Result<GraphRows, StoreError> {
    let plaintext = Zeroizing::new(at_rest::open(passphrase, sealed).map_err(StoreError::Vault)?);
    postcard::from_bytes(&plaintext).map_err(|_| StoreError::Codec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> ContactId {
        let mut a = [0u8; 16];
        a[0] = n;
        a
    }

    #[test]
    fn contact_round_trips() {
        let mut c = Contact::new(id(7), AddedVia::VouchedIntro).with_manual_floor(Tier::Vouched);
        c.status = Status::Paused;
        c.tier = Tier::Trusted;
        let row = ContactRow::from_contact(&c);
        let back = row.to_contact().unwrap();
        assert_eq!(back.id, c.id);
        assert_eq!(back.added_via, c.added_via);
        assert_eq!(back.status, c.status);
        assert_eq!(back.tier, c.tier);
        assert_eq!(back.manual_floor, c.manual_floor);
    }

    #[test]
    fn contact_without_anchor_round_trips() {
        let c = Contact::new(id(8), AddedVia::Invite);
        let row = ContactRow::from_contact(&c);
        assert_eq!(row.manual_floor, None);
        assert_eq!(row.to_contact().unwrap().manual_floor, None);
    }

    #[test]
    fn vouch_round_trips() {
        let v = Vouch { subject: id(1), voucher: id(2), weight: 2, created_at: 1234, revoked: true };
        let back = VouchRow::from_vouch(&v).to_vouch().unwrap();
        assert_eq!(back.subject, v.subject);
        assert_eq!(back.voucher, v.voucher);
        assert_eq!(back.weight, v.weight);
        assert_eq!(back.created_at, v.created_at);
        assert_eq!(back.revoked, v.revoked);
    }

    #[test]
    fn burn_round_trips() {
        let b = BurnSignal { subject: id(1), origin: id(2), created_at: 99 };
        let back = BurnRow::from_burn(&b).to_burn().unwrap();
        assert_eq!(back.subject, b.subject);
        assert_eq!(back.origin, b.origin);
        assert_eq!(back.created_at, b.created_at);
    }

    #[test]
    fn bad_enum_tag_is_rejected() {
        let row = ContactRow {
            contact_id: id(1).to_vec(),
            added_via: "nonsense".into(),
            status: "active".into(),
            tier: 0,
            manual_floor: None,
        };
        assert_eq!(row.to_contact().unwrap_err(), DecodeError::BadEnumTag("added_via"));
    }

    #[test]
    fn bad_contact_id_length_is_rejected() {
        let row = ContactRow {
            contact_id: vec![1, 2, 3],
            added_via: "invite".into(),
            status: "active".into(),
            tier: 0,
            manual_floor: None,
        };
        assert_eq!(row.to_contact().unwrap_err(), DecodeError::BadContactId);
    }

    #[test]
    fn bad_manual_floor_is_rejected() {
        let row = ContactRow {
            contact_id: id(1).to_vec(),
            added_via: "invite".into(),
            status: "active".into(),
            tier: 0,
            manual_floor: Some(99),
        };
        assert_eq!(row.to_contact().unwrap_err(), DecodeError::BadTier);
    }

    const NOW: i64 = 2000;

    /// A small but non-trivial graph: an anchor, a vouched contact, a paused+burned one,
    /// and a revoked vouch — exercising every column and status the layer must preserve.
    fn sample_graph() -> TrustGraph {
        let mut g = TrustGraph::new(TrustParams::default());
        let (anchor, s1, s2) = (id(1), id(2), id(3));
        g.upsert_contact(Contact::new(anchor, AddedVia::Invite).with_manual_floor(Tier::Core));
        g.upsert_contact(Contact::new(s1, AddedVia::VouchedIntro));
        let mut paused = Contact::new(s2, AddedVia::Invite);
        paused.status = Status::Paused;
        g.upsert_contact(paused);

        g.add_vouch(Vouch { subject: s1, voucher: anchor, weight: 3, created_at: 1000, revoked: false });
        g.add_vouch(Vouch { subject: s2, voucher: anchor, weight: 2, created_at: 900, revoked: true });
        g.add_burn(BurnSignal { subject: s2, origin: anchor, created_at: 1100 });

        g.recompute_all(NOW);
        g
    }

    #[test]
    fn whole_graph_round_trips() {
        let g = sample_graph();
        let rows = snapshot(&g);
        assert_eq!(rows.contacts.len(), 3);
        assert_eq!(rows.vouches.len(), 2, "revoked vouches are retained, not dropped");
        assert_eq!(rows.burns.len(), 1);

        let restored = restore(&rows, TrustParams::default()).unwrap();
        assert_eq!(snapshot(&restored), rows, "snapshot must be stable across a restore");
    }

    #[test]
    fn restore_preserves_scores_and_tiers() {
        let g = sample_graph();
        let restored = restore(&snapshot(&g), g.params()).unwrap();
        for c in g.iter_contacts() {
            assert_eq!(restored.contact(&c.id).map(|rc| rc.tier), Some(c.tier), "cached tier");
            let (a, b) = (restored.score(&c.id, NOW), g.score(&c.id, NOW));
            assert!((a - b).abs() < 1e-9, "score mismatch after restore: {a} vs {b}");
        }
    }

    #[test]
    fn snapshot_is_deterministic_regardless_of_insertion_order() {
        // Two graphs with identical contents inserted in different orders must produce
        // byte-identical snapshots (the layer sorts rows into a canonical order).
        let mut g1 = TrustGraph::new(TrustParams::default());
        let mut g2 = TrustGraph::new(TrustParams::default());
        let ids = [id(5), id(2), id(9), id(1)];
        for c in ids {
            g1.upsert_contact(Contact::new(c, AddedVia::Invite));
        }
        for c in ids.iter().rev() {
            g2.upsert_contact(Contact::new(*c, AddedVia::Invite));
        }
        assert_eq!(snapshot(&g1), snapshot(&g2));
    }

    /// Cheap KDF parameters so the encrypted-store tests stay fast.
    const TEST_KDF: KdfParams = KdfParams { m_cost_kib: 64, t_cost: 1, p_cost: 1 };

    #[test]
    fn encrypted_store_round_trips_the_whole_graph() {
        let g = sample_graph();
        let rows = snapshot(&g);

        let sealed = seal_graph(b"open sesame", &rows, TEST_KDF).unwrap();
        let opened = open_graph(b"open sesame", &sealed).unwrap();
        assert_eq!(opened, rows);

        // And the reopened rows still rebuild an equivalent graph.
        let restored = restore(&opened, g.params()).unwrap();
        assert_eq!(snapshot(&restored), rows);
    }

    #[test]
    fn encrypted_store_rejects_a_wrong_passphrase() {
        let rows = snapshot(&sample_graph());
        let sealed = seal_graph(b"correct", &rows, TEST_KDF).unwrap();
        assert_eq!(open_graph(b"incorrect", &sealed).unwrap_err(), StoreError::Vault(VaultError::Decrypt));
    }

    #[test]
    fn encrypted_store_leaks_no_plaintext_handles() {
        // A contact id from the graph must not appear in cleartext in the sealed blob.
        let g = sample_graph();
        let sealed = seal_graph(b"pw", &snapshot(&g), TEST_KDF).unwrap();
        let needle = id(1).to_vec();
        assert!(!sealed.windows(needle.len()).any(|w| w == needle), "contact id leaked at rest");
    }

    #[test]
    fn restore_rejects_malformed_rows() {
        let rows = GraphRows {
            contacts: vec![ContactRow {
                contact_id: vec![1, 2, 3],
                added_via: "invite".into(),
                status: "active".into(),
                tier: 0,
                manual_floor: None,
            }],
            ..Default::default()
        };
        assert!(matches!(restore(&rows, TrustParams::default()), Err(DecodeError::BadContactId)));
    }
}
