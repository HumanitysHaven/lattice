//! Encryption at rest (req `7.3`, `7.6`).
//!
//! A small, auditable **vault** that seals arbitrary bytes under a key derived from a user
//! passphrase, so nothing readable ever touches disk. No home-grown cryptography (`7.3`):
//!
//! - **Key derivation:** Argon2id (memory-hard) over the passphrase and a random salt.
//! - **Encryption:** XChaCha20-Poly1305 AEAD (24-byte random nonce, 256-bit key).
//! - **Integrity:** the full header — version, KDF parameters, salt, nonce — is
//!   authenticated as AEAD associated data, so tampering with the parameters (e.g.
//!   weakening the KDF) is detected, not just tampering with the ciphertext.
//!
//! The derived key lives only in zeroized memory. Decryption is authenticated: a wrong
//! passphrase or any modification is rejected ([`VaultError::Decrypt`]) — there is no
//! distinguishable "wrong password" oracle beyond AEAD failure, which is what later lets a
//! **duress vault** (`7.6`, milestone 1.8) layer two independently-keyed compartments in
//! one indistinguishable blob.
//!
//! The spec named SQLCipher; this pure-Rust vault meets the same at-rest requirement
//! without a native dependency. A queryable encrypted DB can be layered later over the
//! same Argon2id key.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"LATvault";
const VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const KEY_LEN: usize = 32;
/// Fixed header length up to and including the `salt_len` byte.
const HEADER_FIXED: usize = 8 + 1 + 1 + 4 + 4 + 4 + 1;

// Sanity bounds on KDF parameters read from an *untrusted* blob. The parameters live in
// the header and must be used to derive the key *before* the AEAD tag can be checked, so a
// corrupted or hostile blob could otherwise request an enormous allocation (a crash/DoS).
// Legitimate parameters are far below these caps; anything above is rejected as malformed.
const MAX_M_COST_KIB: u32 = 1 << 20; // 1 GiB
const MAX_T_COST: u32 = 1 << 10;
const MAX_P_COST: u32 = 1 << 8;

pub(crate) fn params_within_bounds(p: &KdfParams) -> bool {
    (1..=MAX_M_COST_KIB).contains(&p.m_cost_kib)
        && (1..=MAX_T_COST).contains(&p.t_cost)
        && (1..=MAX_P_COST).contains(&p.p_cost)
}

/// Why a vault operation failed.
#[derive(Debug, PartialEq, Eq)]
pub enum VaultError {
    /// The OS CSPRNG failed to provide entropy.
    Rng,
    /// Invalid KDF parameters, or key derivation failed.
    Kdf,
    /// The sealed blob is structurally invalid (bad magic, version, or length).
    Malformed,
    /// Authenticated decryption failed: wrong passphrase, or the blob was tampered with.
    Decrypt,
}

/// Argon2id cost parameters. Defaults follow OWASP guidance; callers may lower them only
/// where a weaker KDF is acceptable (e.g. fast tests).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Iteration (time) cost.
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl KdfParams {
    /// OWASP-recommended Argon2id parameters (19 MiB, t=2, p=1).
    pub const fn recommended() -> Self {
        Self { m_cost_kib: 19_456, t_cost: 2, p_cost: 1 }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::recommended()
    }
}

/// Seal `plaintext` under `passphrase`, returning a self-describing encrypted blob.
pub fn seal(passphrase: &[u8], plaintext: &[u8], params: KdfParams) -> Result<Vec<u8>, VaultError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut salt).map_err(|_| VaultError::Rng)?;
    getrandom::getrandom(&mut nonce).map_err(|_| VaultError::Rng)?;

    let key = derive_key(passphrase, &salt, params)?;
    let header = build_header(&params, &salt, &nonce);
    let ciphertext = aead_encrypt(key.as_slice(), &nonce, &header, plaintext)?;

    let mut out = header;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a blob produced by [`seal`]. Fails with [`VaultError::Decrypt`] on a wrong
/// passphrase or any tampering.
pub fn open(passphrase: &[u8], sealed: &[u8]) -> Result<Vec<u8>, VaultError> {
    if sealed.len() < HEADER_FIXED || &sealed[0..8] != MAGIC {
        return Err(VaultError::Malformed);
    }
    if sealed[8] != VERSION || sealed[9] != KDF_ARGON2ID {
        return Err(VaultError::Malformed);
    }
    let params = KdfParams {
        m_cost_kib: u32::from_be_bytes(sealed[10..14].try_into().unwrap()),
        t_cost: u32::from_be_bytes(sealed[14..18].try_into().unwrap()),
        p_cost: u32::from_be_bytes(sealed[18..22].try_into().unwrap()),
    };
    // Reject hostile/corrupted parameters before they reach the (memory-hard) KDF.
    if !params_within_bounds(&params) {
        return Err(VaultError::Malformed);
    }
    let salt_len = sealed[22] as usize;
    let header_len = HEADER_FIXED + salt_len + NONCE_LEN;
    if sealed.len() < header_len {
        return Err(VaultError::Malformed);
    }
    let salt = &sealed[HEADER_FIXED..HEADER_FIXED + salt_len];
    let nonce: &[u8; NONCE_LEN] =
        sealed[HEADER_FIXED + salt_len..header_len].try_into().map_err(|_| VaultError::Malformed)?;
    let header = &sealed[..header_len];
    let ciphertext = &sealed[header_len..];

    let key = derive_key(passphrase, salt, params)?;
    aead_decrypt(key.as_slice(), nonce, header, ciphertext)
}

/// Derive a 256-bit key from a passphrase and salt with Argon2id. Shared by the
/// at-rest vault and the deniable [`crate::duress`] vault so there is one audited KDF path.
pub(crate) fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let p = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| VaultError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon.hash_password_into(passphrase, salt, key.as_mut_slice()).map_err(|_| VaultError::Kdf)?;
    Ok(key)
}

/// XChaCha20-Poly1305 seal of `plaintext` with `aad` authenticated. Shared AEAD path.
pub(crate) fn aead_encrypt(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| VaultError::Kdf)?;
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| VaultError::Decrypt)
}

/// XChaCha20-Poly1305 open of `ciphertext` with `aad`. Returns [`VaultError::Decrypt`] on
/// any authentication failure (wrong key or tamper) — no distinguishing oracle.
pub(crate) fn aead_decrypt(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| VaultError::Kdf)?;
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| VaultError::Decrypt)
}

fn build_header(params: &KdfParams, salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_FIXED + salt.len() + nonce.len());
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.push(KDF_ARGON2ID);
    header.extend_from_slice(&params.m_cost_kib.to_be_bytes());
    header.extend_from_slice(&params.t_cost.to_be_bytes());
    header.extend_from_slice(&params.p_cost.to_be_bytes());
    header.push(salt.len() as u8);
    header.extend_from_slice(salt);
    header.extend_from_slice(nonce);
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap parameters so tests are fast — never use these in production.
    const TEST_PARAMS: KdfParams = KdfParams { m_cost_kib: 64, t_cost: 1, p_cost: 1 };

    #[test]
    fn round_trips() {
        let sealed = seal(b"correct horse", b"the social graph", TEST_PARAMS).unwrap();
        assert_eq!(open(b"correct horse", &sealed).unwrap(), b"the social graph");
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let sealed = seal(b"pw", b"", TEST_PARAMS).unwrap();
        assert_eq!(open(b"pw", &sealed).unwrap(), b"");
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let sealed = seal(b"right", b"secret", TEST_PARAMS).unwrap();
        assert_eq!(open(b"wrong", &sealed).unwrap_err(), VaultError::Decrypt);
    }

    #[test]
    fn nothing_plaintext_appears_in_the_blob() {
        let plaintext = b"a very recognisable secret string";
        let sealed = seal(b"pw", plaintext, TEST_PARAMS).unwrap();
        assert!(
            !sealed.windows(plaintext.len()).any(|w| w == plaintext),
            "plaintext must not appear in the sealed blob"
        );
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let mut sealed = seal(b"pw", b"secret", TEST_PARAMS).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert_eq!(open(b"pw", &sealed).unwrap_err(), VaultError::Decrypt);
    }

    #[test]
    fn tampering_with_the_kdf_parameters_is_detected() {
        let mut sealed = seal(b"pw", b"secret", TEST_PARAMS).unwrap();
        // Flip a byte in the authenticated m_cost field (offset 10..14).
        sealed[10] ^= 0xff;
        // Either the AAD mismatch or the changed KDF yields a failure, never plaintext.
        assert!(open(b"pw", &sealed).is_err());
    }

    #[test]
    fn each_seal_uses_fresh_salt_and_nonce() {
        let a = seal(b"pw", b"same", TEST_PARAMS).unwrap();
        let b = seal(b"pw", b"same", TEST_PARAMS).unwrap();
        assert_ne!(a, b, "identical inputs must still produce distinct blobs");
    }

    #[test]
    fn absurd_kdf_parameters_are_rejected_not_executed() {
        // Forge a header whose m_cost is enormous; open() must reject it without trying to
        // allocate gigabytes for the KDF.
        let mut sealed = seal(b"pw", b"secret", TEST_PARAMS).unwrap();
        sealed[10..14].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(open(b"pw", &sealed).unwrap_err(), VaultError::Malformed);
    }

    #[test]
    fn malformed_blobs_are_rejected() {
        assert_eq!(open(b"pw", b"").unwrap_err(), VaultError::Malformed);
        assert_eq!(open(b"pw", b"not a vault at all really").unwrap_err(), VaultError::Malformed);
        let sealed = seal(b"pw", b"x", TEST_PARAMS).unwrap();
        assert_eq!(open(b"pw", &sealed[..sealed.len() - 5]).unwrap_err(), VaultError::Decrypt);
    }
}
