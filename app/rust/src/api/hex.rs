//! Trivial hex encode/decode shared by the identity fingerprint, invite tokens, and contact
//! fingerprints — all opaque byte strings the UI needs to show or let the user paste back in.

pub(crate) fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("must have an even number of hex digits".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "not valid hex".to_string()))
        .collect()
}
