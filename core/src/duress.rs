//! Deniable, multi-compartment vault (req `7.6`, threats `S1`, `S9` — coercion & device loss).
//!
//! Milestone 1.8. Where [`crate::at_rest`] seals one secret under one passphrase, this layers
//! several **independently-keyed compartments** into a single blob so the device can survive
//! coercion ("unlock it or else"):
//!
//! - A **decoy** passphrase opens a believable but innocuous compartment.
//! - The **real** passphrase opens the sensitive one.
//! - Crucially, the two are *cryptographically indistinguishable*. Every compartment ("slot")
//!   is salt + nonce + AEAD ciphertext, all of which are indistinguishable from random, and
//!   unused slots are filled with random bytes. There is **no flag on disk** that says how
//!   many slots are real, so an adversary who forces open the decoy cannot prove a second
//!   compartment exists — they cannot even prove the decoy *is* a decoy.
//!
//! ## Design
//!
//! The blob is a small cleartext geometry header (magic, version, KDF parameters, slot size,
//! slot count) followed by `slot_count` fixed-size slots. The header reveals only the *maximum*
//! capacity, never how much is used. Each slot is:
//!
//! ```text
//! salt(16) | nonce(24) | XChaCha20-Poly1305( len(4) || data || random-pad )  ++ tag(16)
//! ```
//!
//! [`DeniableVault::open`] derives a key from the supplied passphrase against *every* slot's
//! salt and attempts authenticated decryption; the slot whose tag verifies is yours. Empty
//! (random) slots and other passphrases' slots never verify, and failure is reported as the
//! same [`VaultError::Decrypt`] whether the passphrase is wrong or simply not present — no
//! oracle. `open` always performs exactly `slot_count` key derivations regardless of which (if
//! any) slot matches, so its running time does not reveal which compartment was hit.
//!
//! ## Operational notes
//!
//! - **Auth-on-open:** there is no way to read a compartment without its passphrase; the KDF
//!   runs on every open, so authentication is intrinsic, not a checkbox.
//! - **Hidden-vault preservation:** a process that only knows the decoy passphrase must, when
//!   it saves, rewrite *only its own* slot ([`DeniableVault::seal_slot`]) and leave the other
//!   slots' bytes byte-for-byte intact. It cannot read them (they look random) but it must not
//!   clobber them, or the hidden compartment is lost.
//! - **Panic wipe:** [`DeniableVault::wipe_slot`] / [`DeniableVault::wipe_all`] overwrite a
//!   compartment (or all of them) with fresh random bytes, making it indistinguishable from an
//!   always-empty slot — a fast, deniable destroy for a duress button.

use crate::at_rest::{self, KdfParams, VaultError, NONCE_LEN, SALT_LEN};

const MAGIC: &[u8; 8] = b"LATdures";
const VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;

const LEN_PREFIX: usize = 4;
const TAG_LEN: usize = 16;
/// Per-slot bytes that are not usable plaintext: salt + nonce + length prefix + AEAD tag.
const SLOT_OVERHEAD: usize = SALT_LEN + NONCE_LEN + LEN_PREFIX + TAG_LEN;
/// Header: magic(8) version(1) kdf(1) m(4) t(4) p(4) slot_size(4) slot_count(1).
const HEADER_LEN: usize = 8 + 1 + 1 + 4 + 4 + 4 + 4 + 1;

/// Upper bound on a single compartment's plaintext (16 MiB). Guards `from_bytes` against a
/// hostile header that claims an absurd slot size.
const MAX_CAPACITY: usize = 16 * 1024 * 1024;
/// Upper bound on the number of slots an untrusted header may declare.
const MAX_SLOTS: u8 = 64;

/// A deniable vault holding several independently-keyed, indistinguishable compartments.
///
/// Construct with [`DeniableVault::new`], populate slots with [`DeniableVault::seal_slot`],
/// read with [`DeniableVault::open`], and persist with [`DeniableVault::to_bytes`] /
/// [`DeniableVault::from_bytes`].
pub struct DeniableVault {
    params: KdfParams,
    /// Total bytes per slot (`capacity + SLOT_OVERHEAD`).
    slot_size: usize,
    /// `slot_count` opaque slots, each exactly `slot_size` bytes.
    slots: Vec<Vec<u8>>,
}

impl core::fmt::Debug for DeniableVault {
    /// Redacted: prints only the public geometry, never the slot bytes, so the vault cannot
    /// be accidentally logged into plaintext form.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeniableVault")
            .field("slot_count", &self.slots.len())
            .field("capacity", &self.capacity())
            .field("slots", &"<redacted>")
            .finish()
    }
}

impl DeniableVault {
    /// Create a vault with `slot_count` compartments, each able to hold up to `capacity`
    /// plaintext bytes, keyed via Argon2id with `params`. All slots start as fresh random
    /// bytes, so a brand-new vault opens to nothing under any passphrase.
    pub fn new(slot_count: u8, capacity: usize, params: KdfParams) -> Result<Self, VaultError> {
        if slot_count == 0 || slot_count > MAX_SLOTS {
            return Err(VaultError::Malformed);
        }
        if capacity == 0 || capacity > MAX_CAPACITY {
            return Err(VaultError::Malformed);
        }
        if !at_rest::params_within_bounds(&params) {
            return Err(VaultError::Kdf);
        }
        let slot_size = capacity + SLOT_OVERHEAD;
        let mut slots = Vec::with_capacity(slot_count as usize);
        for _ in 0..slot_count {
            slots.push(random_bytes(slot_size)?);
        }
        Ok(Self { params, slot_size, slots })
    }

    /// Maximum plaintext bytes a single compartment can hold.
    pub fn capacity(&self) -> usize {
        self.slot_size - SLOT_OVERHEAD
    }

    /// Number of compartments (the only quantity an observer can learn from the blob).
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Seal `plaintext` into compartment `index` under `passphrase`, overwriting whatever was
    /// there. Other slots are left untouched, which is what lets a decoy-only process save
    /// without destroying a hidden compartment it cannot see.
    pub fn seal_slot(&mut self, index: usize, passphrase: &[u8], plaintext: &[u8]) -> Result<(), VaultError> {
        if index >= self.slots.len() {
            return Err(VaultError::Malformed);
        }
        if plaintext.len() > self.capacity() {
            return Err(VaultError::Malformed);
        }

        // Inner buffer is constant-size (LEN_PREFIX + capacity); the tail is random so the
        // padding carries no structure even once a slot is opened.
        let mut inner = random_bytes(LEN_PREFIX + self.capacity())?;
        inner[..LEN_PREFIX].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
        inner[LEN_PREFIX..LEN_PREFIX + plaintext.len()].copy_from_slice(plaintext);

        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut salt).map_err(|_| VaultError::Rng)?;
        getrandom::getrandom(&mut nonce).map_err(|_| VaultError::Rng)?;

        let key = at_rest::derive_key(passphrase, &salt, self.params)?;
        let aad = self.slot_aad(index);
        let ciphertext = at_rest::aead_encrypt(key.as_slice(), &nonce, &aad, &inner)?;

        let mut slot = Vec::with_capacity(self.slot_size);
        slot.extend_from_slice(&salt);
        slot.extend_from_slice(&nonce);
        slot.extend_from_slice(&ciphertext);
        debug_assert_eq!(slot.len(), self.slot_size);
        self.slots[index] = slot;
        Ok(())
    }

    /// Open whichever compartment `passphrase` unlocks, returning its plaintext. Every slot is
    /// attempted (constant number of key derivations); [`VaultError::Decrypt`] is returned if
    /// none matches, indistinguishable from a wrong passphrase.
    pub fn open(&self, passphrase: &[u8]) -> Result<Vec<u8>, VaultError> {
        let mut found: Option<Vec<u8>> = None;
        for (index, slot) in self.slots.iter().enumerate() {
            // A correctly-sized slot always splits cleanly; this only guards corrupt input.
            if slot.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
                continue;
            }
            let salt = &slot[..SALT_LEN];
            let nonce: &[u8; NONCE_LEN] = match slot[SALT_LEN..SALT_LEN + NONCE_LEN].try_into() {
                Ok(n) => n,
                Err(_) => continue,
            };
            let ciphertext = &slot[SALT_LEN + NONCE_LEN..];

            let key = at_rest::derive_key(passphrase, salt, self.params)?;
            let aad = self.slot_aad(index);
            if let Ok(inner) = at_rest::aead_decrypt(key.as_slice(), nonce, &aad, ciphertext) {
                if found.is_none() {
                    if let Some(plaintext) = parse_inner(&inner, self.capacity()) {
                        found = Some(plaintext);
                    }
                }
                // Keep iterating so the running time does not reveal the matching slot.
            }
        }
        found.ok_or(VaultError::Decrypt)
    }

    /// Destroy compartment `index` by overwriting it with fresh random bytes. Afterwards it is
    /// indistinguishable from a slot that was never written — a deniable, irreversible wipe.
    pub fn wipe_slot(&mut self, index: usize) -> Result<(), VaultError> {
        if index >= self.slots.len() {
            return Err(VaultError::Malformed);
        }
        self.slots[index] = random_bytes(self.slot_size)?;
        Ok(())
    }

    /// Destroy every compartment (panic button). All slots become fresh random bytes.
    pub fn wipe_all(&mut self) -> Result<(), VaultError> {
        for slot in &mut self.slots {
            *slot = random_bytes(self.slot_size)?;
        }
        Ok(())
    }

    /// Serialize the whole vault to a single blob. Its length depends only on the geometry
    /// (slot count and size), never on how many compartments are actually in use.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.slots.len() * self.slot_size);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(KDF_ARGON2ID);
        out.extend_from_slice(&self.params.m_cost_kib.to_be_bytes());
        out.extend_from_slice(&self.params.t_cost.to_be_bytes());
        out.extend_from_slice(&self.params.p_cost.to_be_bytes());
        out.extend_from_slice(&(self.slot_size as u32).to_be_bytes());
        out.push(self.slots.len() as u8);
        for slot in &self.slots {
            out.extend_from_slice(slot);
        }
        out
    }

    /// Parse a blob produced by [`to_bytes`](DeniableVault::to_bytes). Rejects structurally
    /// invalid input and hostile geometry/KDF parameters before any work is done.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() < HEADER_LEN || &bytes[0..8] != MAGIC {
            return Err(VaultError::Malformed);
        }
        if bytes[8] != VERSION || bytes[9] != KDF_ARGON2ID {
            return Err(VaultError::Malformed);
        }
        let params = KdfParams {
            m_cost_kib: u32::from_be_bytes(bytes[10..14].try_into().unwrap()),
            t_cost: u32::from_be_bytes(bytes[14..18].try_into().unwrap()),
            p_cost: u32::from_be_bytes(bytes[18..22].try_into().unwrap()),
        };
        if !at_rest::params_within_bounds(&params) {
            return Err(VaultError::Malformed);
        }
        let slot_size = u32::from_be_bytes(bytes[22..26].try_into().unwrap()) as usize;
        let slot_count = bytes[26];
        if slot_count == 0 || slot_count > MAX_SLOTS {
            return Err(VaultError::Malformed);
        }
        if slot_size <= SLOT_OVERHEAD || slot_size - SLOT_OVERHEAD > MAX_CAPACITY {
            return Err(VaultError::Malformed);
        }
        let expected = HEADER_LEN + slot_count as usize * slot_size;
        if bytes.len() != expected {
            return Err(VaultError::Malformed);
        }
        let mut slots = Vec::with_capacity(slot_count as usize);
        let mut offset = HEADER_LEN;
        for _ in 0..slot_count {
            slots.push(bytes[offset..offset + slot_size].to_vec());
            offset += slot_size;
        }
        Ok(Self { params, slot_size, slots })
    }

    /// Associated data binding a slot's ciphertext to the vault geometry and its index, so a
    /// slot cannot be silently relocated, reordered, or transplanted into another vault.
    fn slot_aad(&self, index: usize) -> Vec<u8> {
        let mut aad = Vec::with_capacity(HEADER_LEN + 1);
        aad.extend_from_slice(MAGIC);
        aad.push(VERSION);
        aad.push(KDF_ARGON2ID);
        aad.extend_from_slice(&self.params.m_cost_kib.to_be_bytes());
        aad.extend_from_slice(&self.params.t_cost.to_be_bytes());
        aad.extend_from_slice(&self.params.p_cost.to_be_bytes());
        aad.extend_from_slice(&(self.slot_size as u32).to_be_bytes());
        aad.push(self.slots.len() as u8);
        aad.push(index as u8);
        aad
    }
}

fn random_bytes(len: usize) -> Result<Vec<u8>, VaultError> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).map_err(|_| VaultError::Rng)?;
    Ok(buf)
}

/// Recover the plaintext from a decrypted inner buffer, rejecting a length that overflows the
/// compartment (which can only happen if a verified buffer is nonetheless internally corrupt).
fn parse_inner(inner: &[u8], capacity: usize) -> Option<Vec<u8>> {
    if inner.len() < LEN_PREFIX {
        return None;
    }
    let len = u32::from_be_bytes(inner[..LEN_PREFIX].try_into().ok()?) as usize;
    if len > capacity || LEN_PREFIX + len > inner.len() {
        return None;
    }
    Some(inner[LEN_PREFIX..LEN_PREFIX + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap Argon2id parameters so the test suite stays fast; never use these in production.
    fn test_params() -> KdfParams {
        KdfParams { m_cost_kib: 64, t_cost: 1, p_cost: 1 }
    }

    fn new_vault(slots: u8, capacity: usize) -> DeniableVault {
        DeniableVault::new(slots, capacity, test_params()).unwrap()
    }

    #[test]
    fn a_fresh_vault_opens_to_nothing() {
        let vault = new_vault(3, 256);
        assert_eq!(vault.open(b"anything").unwrap_err(), VaultError::Decrypt);
        assert_eq!(vault.open(b"another guess").unwrap_err(), VaultError::Decrypt);
    }

    #[test]
    fn seal_then_open_round_trips() {
        let mut vault = new_vault(2, 256);
        let secret = b"the real plaintext";
        vault.seal_slot(0, b"correct horse", secret).unwrap();
        assert_eq!(vault.open(b"correct horse").unwrap(), secret);
        assert_eq!(vault.open(b"wrong passphrase").unwrap_err(), VaultError::Decrypt);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let mut vault = new_vault(2, 64);
        vault.seal_slot(0, b"pw", b"").unwrap();
        assert_eq!(vault.open(b"pw").unwrap(), b"");
    }

    #[test]
    fn plaintext_at_capacity_round_trips() {
        let mut vault = new_vault(1, 128);
        let secret = vec![0xABu8; vault.capacity()];
        vault.seal_slot(0, b"pw", &secret).unwrap();
        assert_eq!(vault.open(b"pw").unwrap(), secret);
    }

    #[test]
    fn plaintext_over_capacity_is_rejected() {
        let mut vault = new_vault(1, 64);
        let too_big = vec![0u8; vault.capacity() + 1];
        assert_eq!(vault.seal_slot(0, b"pw", &too_big).unwrap_err(), VaultError::Malformed);
    }

    #[test]
    fn decoy_and_real_compartments_are_independent() {
        let mut vault = new_vault(3, 256);
        vault.seal_slot(0, b"real-pass", b"sensitive contacts").unwrap();
        vault.seal_slot(1, b"decoy-pass", b"harmless shopping list").unwrap();

        assert_eq!(vault.open(b"real-pass").unwrap(), b"sensitive contacts");
        assert_eq!(vault.open(b"decoy-pass").unwrap(), b"harmless shopping list");
        assert_eq!(vault.open(b"neither").unwrap_err(), VaultError::Decrypt);
    }

    #[test]
    fn the_blob_size_is_constant_regardless_of_how_many_slots_are_used() {
        // One vault uses a single compartment; the other uses two. Same geometry => same size,
        // so the byte length leaks nothing about how many compartments are real.
        let mut one = new_vault(3, 256);
        one.seal_slot(0, b"a", b"only one used").unwrap();

        let mut two = new_vault(3, 256);
        two.seal_slot(0, b"a", b"first").unwrap();
        two.seal_slot(1, b"b", b"second").unwrap();

        assert_eq!(one.to_bytes().len(), two.to_bytes().len());
    }

    #[test]
    fn saving_the_decoy_preserves_a_hidden_compartment() {
        // Model a decoy-only process: it re-seals *its* slot but must not disturb the real one.
        let mut vault = new_vault(2, 256);
        vault.seal_slot(0, b"real-pass", b"hidden truth").unwrap();
        vault.seal_slot(1, b"decoy-pass", b"first decoy").unwrap();

        let real_slot_before = vault.slots[0].clone();
        vault.seal_slot(1, b"decoy-pass", b"updated decoy").unwrap();

        assert_eq!(vault.slots[0], real_slot_before, "real slot must be byte-for-byte intact");
        assert_eq!(vault.open(b"real-pass").unwrap(), b"hidden truth");
        assert_eq!(vault.open(b"decoy-pass").unwrap(), b"updated decoy");
    }

    #[test]
    fn bytes_round_trip_through_serialization() {
        let mut vault = new_vault(3, 256);
        vault.seal_slot(0, b"real-pass", b"persisted secret").unwrap();
        vault.seal_slot(2, b"decoy-pass", b"persisted decoy").unwrap();

        let blob = vault.to_bytes();
        let restored = DeniableVault::from_bytes(&blob).unwrap();

        assert_eq!(restored.open(b"real-pass").unwrap(), b"persisted secret");
        assert_eq!(restored.open(b"decoy-pass").unwrap(), b"persisted decoy");
        assert_eq!(restored.open(b"nope").unwrap_err(), VaultError::Decrypt);
    }

    #[test]
    fn wiping_a_slot_destroys_only_that_compartment() {
        let mut vault = new_vault(2, 256);
        vault.seal_slot(0, b"real-pass", b"to be destroyed").unwrap();
        vault.seal_slot(1, b"decoy-pass", b"survivor").unwrap();

        vault.wipe_slot(0).unwrap();

        assert_eq!(vault.open(b"real-pass").unwrap_err(), VaultError::Decrypt);
        assert_eq!(vault.open(b"decoy-pass").unwrap(), b"survivor");
    }

    #[test]
    fn wiping_all_slots_destroys_everything() {
        let mut vault = new_vault(2, 256);
        vault.seal_slot(0, b"real-pass", b"x").unwrap();
        vault.seal_slot(1, b"decoy-pass", b"y").unwrap();

        vault.wipe_all().unwrap();

        assert_eq!(vault.open(b"real-pass").unwrap_err(), VaultError::Decrypt);
        assert_eq!(vault.open(b"decoy-pass").unwrap_err(), VaultError::Decrypt);
    }

    #[test]
    fn tampering_with_a_slot_byte_makes_it_unopenable() {
        let mut vault = new_vault(2, 256);
        vault.seal_slot(0, b"real-pass", b"integrity matters").unwrap();

        let mut blob = vault.to_bytes();
        // Flip a byte inside the first slot's ciphertext region.
        let target = HEADER_LEN + SALT_LEN + NONCE_LEN + 2;
        blob[target] ^= 0x01;

        let restored = DeniableVault::from_bytes(&blob).unwrap();
        assert_eq!(restored.open(b"real-pass").unwrap_err(), VaultError::Decrypt);
    }

    #[test]
    fn from_bytes_rejects_truncated_and_corrupt_blobs() {
        let mut vault = new_vault(2, 256);
        vault.seal_slot(0, b"pw", b"data").unwrap();
        let blob = vault.to_bytes();

        assert_eq!(DeniableVault::from_bytes(&[]).unwrap_err(), VaultError::Malformed);
        assert_eq!(DeniableVault::from_bytes(&blob[..HEADER_LEN]).unwrap_err(), VaultError::Malformed);

        let mut bad_magic = blob.clone();
        bad_magic[0] ^= 0xFF;
        assert_eq!(DeniableVault::from_bytes(&bad_magic).unwrap_err(), VaultError::Malformed);

        let mut truncated = blob.clone();
        truncated.pop();
        assert_eq!(DeniableVault::from_bytes(&truncated).unwrap_err(), VaultError::Malformed);
    }

    #[test]
    fn from_bytes_rejects_a_hostile_slot_count() {
        let mut vault = new_vault(1, 64);
        vault.seal_slot(0, b"pw", b"d").unwrap();
        let mut blob = vault.to_bytes();
        // Claim more slots than the body actually contains.
        blob[26] = MAX_SLOTS;
        assert_eq!(DeniableVault::from_bytes(&blob).unwrap_err(), VaultError::Malformed);
    }

    #[test]
    fn new_rejects_degenerate_geometry() {
        assert_eq!(DeniableVault::new(0, 64, test_params()).unwrap_err(), VaultError::Malformed);
        assert_eq!(DeniableVault::new(1, 0, test_params()).unwrap_err(), VaultError::Malformed);
        let huge = KdfParams { m_cost_kib: u32::MAX, t_cost: 1, p_cost: 1 };
        assert_eq!(DeniableVault::new(1, 64, huge).unwrap_err(), VaultError::Kdf);
    }
}
