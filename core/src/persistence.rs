//! Persistence mapping for the local trust store.
//!
//! This module is **storage-engine-agnostic on purpose**. It defines the SQL schema
//! (matching `docs/technical-spec.md` §4) and converts the in-memory trust types to and
//! from plain *row* structs built only from primitive column values. The actual database
//! (SQLCipher, encrypted at rest under an Argon2id-derived key — req `7.3`/`7.6`) is wired
//! in a later milestone; keeping this layer pure means it stays unit-testable with no I/O
//! and no native dependency, and the encryption boundary lives entirely below it.
//!
//! Column-type conventions:
//! - `ContactId` (`[u8; 16]`) ↔ `BLOB`, represented here as `Vec<u8>`.
//! - enums ↔ short `TEXT` tags.
//! - timestamps ↔ `INTEGER` (unix seconds).

use crate::trust::{AddedVia, BurnSignal, Contact, ContactId, Status, Tier, Vouch};

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
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
}
