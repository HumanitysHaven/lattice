//! Fixed-size opaque framing (req `7.4`, threat `S5` — metadata-resistant transport).
//!
//! The transport's safety rests on an **untrusted relay seeing only opaque, equal-sized
//! blobs** in random queues, so it cannot infer anything from message length, distinguish a
//! one-word reply from a long confession, or fingerprint traffic. This module is that
//! length-hiding kernel, kept pure and offline so it can be audited and tested with zero
//! network: the Tor/queue plumbing ([`crate::transport`]) and the ratchet that supplies the
//! per-message key ([`crate::messaging`], libsignal) layer on top later.
//!
//! Every payload — whatever its real size — is first **padded into a fixed-size block**
//! (length prefix + payload + zero pad to [`BLOCK_SIZE`]) and then sealed with
//! XChaCha20-Poly1305 (the audited AEAD shared with [`crate::at_rest`]). The result is always
//! exactly [`SEALED_LEN`] bytes:
//!
//! ```text
//! nonce(24) | XChaCha20-Poly1305( len(4) || payload || 0-pad )  ++ tag(16)
//! ```
//!
//! Because the plaintext is padded *before* encryption, the ciphertext — and therefore the
//! on-wire blob — carries no length signal at all. The padding is inside the AEAD, so it is
//! confidential and integrity-protected; its content is irrelevant to security and is simply
//! zeroed. Payloads larger than [`MAX_PAYLOAD`] are rejected here and must be chunked by the
//! caller (each chunk becomes its own indistinguishable block).
//!
//! The per-message `key` is supplied by the caller and is expected to be a fresh symmetric
//! key from the message ratchet; reusing a key across messages is a caller error. Replay and
//! ordering are the session layer's responsibility — this module only guarantees
//! confidentiality, integrity, and length-uniformity of a single block.

use zeroize::Zeroizing;

use crate::at_rest::{aead_decrypt, aead_encrypt, KEY_LEN, NONCE_LEN};
use crate::transport::Blob;

/// Bytes that prefix the payload inside a block, encoding the true payload length.
const LEN_PREFIX: usize = 4;
/// AEAD authentication tag length (XChaCha20-Poly1305).
const TAG_LEN: usize = 16;

/// Fixed plaintext block size: every payload is padded to exactly this before sealing.
///
/// 16 KiB matches the SimpleX/SMP transport block so traffic blends with that ecosystem and
/// comfortably fits a chat message; larger payloads are chunked by the caller.
pub const BLOCK_SIZE: usize = 16 * 1024;

/// Largest payload that fits in a single block (the rest of the block is length prefix).
pub const MAX_PAYLOAD: usize = BLOCK_SIZE - LEN_PREFIX;

/// Exact size of every sealed blob, regardless of payload length. This constant *is* the
/// metadata-resistance guarantee: on the wire, all blobs are indistinguishable by size.
pub const SEALED_LEN: usize = NONCE_LEN + BLOCK_SIZE + TAG_LEN;

/// Why framing failed.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The payload is larger than [`MAX_PAYLOAD`]; chunk it into multiple blocks.
    TooLarge,
    /// The OS CSPRNG failed to provide a nonce.
    Rng,
    /// The blob is not exactly [`SEALED_LEN`] bytes, or its declared payload length is invalid.
    Malformed,
    /// Authenticated decryption failed: wrong key or the blob was tampered with.
    Crypto,
}

/// Pad `payload` into a fixed-size block and seal it under `key`, returning an opaque blob of
/// exactly [`SEALED_LEN`] bytes. Two calls with the same inputs yield different blobs (fresh
/// random nonce) but always the same length.
pub fn seal(key: &[u8; KEY_LEN], payload: &[u8]) -> Result<Blob, FrameError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(FrameError::TooLarge);
    }

    // Build the padded plaintext block. Held in zeroizing memory: it carries the cleartext
    // payload and should not linger after sealing.
    let mut block = Zeroizing::new(vec![0u8; BLOCK_SIZE]);
    block[..LEN_PREFIX].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    block[LEN_PREFIX..LEN_PREFIX + payload.len()].copy_from_slice(payload);

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| FrameError::Rng)?;

    let ciphertext = aead_encrypt(key, &nonce, &[], &block).map_err(|_| FrameError::Crypto)?;

    let mut out = Vec::with_capacity(SEALED_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    debug_assert_eq!(out.len(), SEALED_LEN);
    Ok(Blob(out))
}

/// Pad an **already-encrypted** payload into a fixed-size block for the wire, *without* adding
/// another encryption layer. Use this for content that is already confidential — e.g. Double
/// Ratchet ([`crate::messaging`]) ciphertext — so the relay sees only uniform [`BLOCK_SIZE`]
/// blobs and learns nothing from length. Returns exactly [`BLOCK_SIZE`] bytes.
///
/// Confidentiality and integrity must already be provided by the payload (the ratchet's AEAD);
/// the padding itself is not authenticated, but a truncated or altered block simply fails to
/// decrypt at the ratchet, which is no worse than a relay dropping the message.
pub fn pad(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(FrameError::TooLarge);
    }
    let mut block = vec![0u8; BLOCK_SIZE];
    block[..LEN_PREFIX].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    block[LEN_PREFIX..LEN_PREFIX + payload.len()].copy_from_slice(payload);
    Ok(block)
}

/// Recover a payload from a block produced by [`pad`]. Rejects any block that is not exactly
/// [`BLOCK_SIZE`] bytes or whose declared length is out of range ([`FrameError::Malformed`]).
pub fn unpad(block: &[u8]) -> Result<Vec<u8>, FrameError> {
    if block.len() != BLOCK_SIZE {
        return Err(FrameError::Malformed);
    }
    let len = u32::from_be_bytes(block[..LEN_PREFIX].try_into().unwrap()) as usize;
    if len > MAX_PAYLOAD {
        return Err(FrameError::Malformed);
    }
    Ok(block[LEN_PREFIX..LEN_PREFIX + len].to_vec())
}

/// Open a blob produced by [`seal`], returning the original payload. Rejects any blob that is
/// not exactly [`SEALED_LEN`] bytes ([`FrameError::Malformed`]) and any wrong-key or tampered
/// blob ([`FrameError::Crypto`]) — there is no length or content oracle.
pub fn open(key: &[u8; KEY_LEN], blob: &Blob) -> Result<Vec<u8>, FrameError> {
    if blob.0.len() != SEALED_LEN {
        return Err(FrameError::Malformed);
    }
    let nonce: &[u8; NONCE_LEN] = blob.0[..NONCE_LEN].try_into().map_err(|_| FrameError::Malformed)?;
    let ciphertext = &blob.0[NONCE_LEN..];

    let block = Zeroizing::new(aead_decrypt(key, nonce, &[], ciphertext).map_err(|_| FrameError::Crypto)?);
    // A verified block is always BLOCK_SIZE; this guards only against an impossible internal
    // mismatch rather than attacker input (which the tag already rejected).
    if block.len() != BLOCK_SIZE {
        return Err(FrameError::Malformed);
    }

    let len = u32::from_be_bytes(block[..LEN_PREFIX].try_into().unwrap()) as usize;
    if len > MAX_PAYLOAD {
        return Err(FrameError::Malformed);
    }
    Ok(block[LEN_PREFIX..LEN_PREFIX + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; KEY_LEN] {
        [byte; KEY_LEN]
    }

    #[test]
    fn round_trips_payloads_of_every_size() {
        let k = key(0x11);
        for len in [0usize, 1, 16, 100, 1024, MAX_PAYLOAD] {
            let payload = vec![0xA5u8; len];
            let blob = seal(&k, &payload).unwrap();
            assert_eq!(open(&k, &blob).unwrap(), payload, "round-trip failed at len {len}");
        }
    }

    #[test]
    fn every_blob_is_the_same_size_regardless_of_payload() {
        // The core metadata-resistance property: a 1-byte ack and a max-size message are
        // indistinguishable by length on the wire.
        let k = key(0x22);
        let tiny = seal(&k, b"y").unwrap();
        let huge = seal(&k, &vec![0u8; MAX_PAYLOAD]).unwrap();
        let empty = seal(&k, b"").unwrap();
        assert_eq!(tiny.0.len(), SEALED_LEN);
        assert_eq!(huge.0.len(), SEALED_LEN);
        assert_eq!(empty.0.len(), SEALED_LEN);
    }

    #[test]
    fn resealing_the_same_payload_changes_the_blob_but_not_its_length() {
        let k = key(0x33);
        let payload = b"identical content";
        let a = seal(&k, payload).unwrap();
        let b = seal(&k, payload).unwrap();
        assert_ne!(a.0, b.0, "fresh nonce must make the ciphertext differ");
        assert_eq!(a.0.len(), b.0.len());
        assert_eq!(open(&k, &a).unwrap(), open(&k, &b).unwrap());
    }

    #[test]
    fn a_payload_over_the_limit_is_rejected() {
        let k = key(0x44);
        let too_big = vec![0u8; MAX_PAYLOAD + 1];
        assert_eq!(seal(&k, &too_big).unwrap_err(), FrameError::TooLarge);
    }

    #[test]
    fn a_wrong_key_cannot_open_the_blob() {
        let blob = seal(&key(0x55), b"secret").unwrap();
        assert_eq!(open(&key(0x56), &blob).unwrap_err(), FrameError::Crypto);
    }

    #[test]
    fn tampering_with_any_region_is_detected() {
        let k = key(0x66);
        let blob = seal(&k, b"do not modify").unwrap();
        for idx in [0usize, NONCE_LEN, NONCE_LEN + 10, SEALED_LEN - 1] {
            let mut t = blob.clone();
            t.0[idx] ^= 0x01;
            assert_eq!(open(&k, &t).unwrap_err(), FrameError::Crypto, "tamper at {idx} not caught");
        }
    }

    #[test]
    fn a_blob_of_the_wrong_size_is_malformed() {
        let k = key(0x77);
        let blob = seal(&k, b"data").unwrap();

        let mut short = blob.clone();
        short.0.pop();
        assert_eq!(open(&k, &short).unwrap_err(), FrameError::Malformed);

        let mut long = blob.clone();
        long.0.push(0);
        assert_eq!(open(&k, &long).unwrap_err(), FrameError::Malformed);

        assert_eq!(open(&k, &Blob(Vec::new())).unwrap_err(), FrameError::Malformed);
    }

    #[test]
    fn pad_unpad_round_trips_and_hides_length() {
        for len in [0usize, 1, 200, 4096, MAX_PAYLOAD] {
            let payload = vec![0x5Au8; len];
            let block = pad(&payload).unwrap();
            assert_eq!(block.len(), BLOCK_SIZE, "every padded block is the same size");
            assert_eq!(unpad(&block).unwrap(), payload);
        }
    }

    #[test]
    fn pad_rejects_oversized_and_unpad_rejects_wrong_size() {
        assert_eq!(pad(&vec![0u8; MAX_PAYLOAD + 1]).unwrap_err(), FrameError::TooLarge);
        assert_eq!(unpad(&[0u8; BLOCK_SIZE - 1]).unwrap_err(), FrameError::Malformed);
        let mut block = pad(b"hi").unwrap();
        block.push(0);
        assert_eq!(unpad(&block).unwrap_err(), FrameError::Malformed);
    }

    #[test]
    fn a_blob_leaks_no_plaintext_bytes() {
        // The payload must not appear in the clear anywhere in the sealed blob.
        let k = key(0x88);
        let marker = b"UNIQUE-NEEDLE-7f3a";
        let blob = seal(&k, marker).unwrap();
        assert!(!blob.0.windows(marker.len()).any(|w| w == marker), "plaintext marker found in sealed blob");
    }
}
