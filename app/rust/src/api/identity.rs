//! First FFI vertical slice: identity creation and recovery (Phase 1.1, `7.1`).
//!
//! Deliberately the first thing exposed to the Flutter shell — no network, no async, no
//! persistence yet, just the audited Ed25519 + BIP39 identity core
//! ([`lattice_core::identity`]) reachable from a real screen. Stateless for now: each call
//! generates or restores an identity and hands back what the UI needs to display; wiring the
//! result into the encrypted local store ([`lattice_core::at_rest`]) is a later step, not
//! this one.

use lattice_core::identity::{Identity, RecoveryPhrase};

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
        local_id_hex: hex_encode(&identity.local_id()),
        nickname: identity.nickname().to_string(),
        recovery_words: identity.recovery_phrase().words().into_iter().map(String::from).collect(),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
