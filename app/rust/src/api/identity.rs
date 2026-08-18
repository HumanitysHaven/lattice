//! First FFI vertical slice: identity creation, recovery, and local persistence
//! (Phase 1.1/1.2, `7.1`/`7.3`).
//!
//! Deliberately the first thing exposed to the Flutter shell — no network, no async, just
//! the audited Ed25519 + BIP39 identity core ([`lattice_core::identity`]) and its
//! passphrase-sealed local storage ([`lattice_core::at_rest`], via
//! [`lattice_core::identity::seal_identity`]/`open_identity`) reachable from real screens.
//!
//! Stateless by design, same as [`create_identity`]/[`restore_identity`]: nothing here holds
//! an `Identity` in memory between calls. [`seal_current_identity`] takes the recovery words
//! and nickname the UI already has (from [`IdentitySummary`]) and returns sealed bytes;
//! [`unlock_identity`] takes sealed bytes and a passphrase and returns a summary. **Where
//! those bytes live on disk is deliberately not this module's concern** — that's
//! platform-specific (native filesystem vs. web storage) and belongs in Dart
//! (`path_provider` et al.), keeping this crate as thin a translation edge as `core` itself
//! is a pure one.

use lattice_core::at_rest::KdfParams;
use lattice_core::identity::{self, Identity, RecoveryPhrase};

use crate::api::hex;

/// What a "create" or "restore" screen needs to show the user immediately afterward.
#[derive(Debug, Clone)]
pub struct IdentitySummary {
    /// The local, non-networkable handle for this identity, as lowercase hex — a short,
    /// stable fingerprint the user can compare across devices.
    pub local_id_hex: String,
    pub nickname: String,
    /// The 24-word BIP39 recovery phrase. Highly sensitive: the UI must treat this like the
    /// secret it is (no analytics, no accidental logging, cleared from the screen once the
    /// user confirms they've written it down).
    pub recovery_words: Vec<String>,
}

fn summarize(identity: &Identity) -> IdentitySummary {
    IdentitySummary {
        local_id_hex: hex::encode(&identity.local_id()),
        nickname: identity.nickname().to_string(),
        recovery_words: identity.recovery_phrase().words().into_iter().map(String::from).collect(),
    }
}

/// Generate a brand-new identity from OS randomness.
#[flutter_rust_bridge::frb(sync)]
pub fn create_identity(nickname: String) -> Result<IdentitySummary, String> {
    let identity = Identity::generate(&nickname).map_err(|err| format!("{err:?}"))?;
    Ok(summarize(&identity))
}

/// Deterministically restore an identity from a 24-word recovery phrase the user typed in.
/// The same phrase always yields the same `local_id_hex` — that's how the user confirms
/// they entered it correctly.
#[flutter_rust_bridge::frb(sync)]
pub fn restore_identity(recovery_phrase: String, nickname: String) -> Result<IdentitySummary, String> {
    let phrase = RecoveryPhrase::new(recovery_phrase);
    let identity = Identity::from_recovery(&phrase, &nickname).map_err(|err| format!("{err:?}"))?;
    Ok(summarize(&identity))
}

/// Seal the identity described by `recovery_words`/`nickname` (as already returned by
/// [`create_identity`] or [`restore_identity`]) under `passphrase`, so the caller can write
/// the result to local storage and skip the create/restore screens on the next launch. The
/// passphrase protects this local copy; the recovery phrase remains the real backup.
#[flutter_rust_bridge::frb(sync)]
pub fn seal_current_identity(
    recovery_words: Vec<String>,
    nickname: String,
    passphrase: String,
) -> Result<Vec<u8>, String> {
    let phrase = RecoveryPhrase::new(recovery_words.join(" "));
    let restored = Identity::from_recovery(&phrase, &nickname).map_err(|err| format!("{err:?}"))?;
    identity::seal_identity(passphrase.as_bytes(), &restored, KdfParams::recommended())
        .map_err(|err| format!("{err:?}"))
}

/// Open a previously-sealed identity (bytes read by the caller from local storage) under
/// `passphrase`. Fails the same way for a wrong passphrase as for a tampered/corrupted file
/// — no oracle beyond "it didn't open".
#[flutter_rust_bridge::frb(sync)]
pub fn unlock_identity(passphrase: String, sealed: Vec<u8>) -> Result<IdentitySummary, String> {
    let restored =
        identity::open_identity(passphrase.as_bytes(), &sealed).map_err(|err| format!("{err:?}"))?;
    Ok(summarize(&restored))
}
