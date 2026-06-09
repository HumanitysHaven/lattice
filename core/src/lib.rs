//! `lattice-core` — the security-critical core for a local-first web of trust
//! designed for at-risk communities.
//!
//! Everything in this crate runs **on the user's own device**. There is no server
//! component here and no module may introduce one: the design's safety rests on the
//! fact that the operator/network is powerless (see `docs/threat-model.md` req `7.5`).
//!
//! The [`trust`] engine is the first fully-implemented module: it is pure and offline and
//! can be developed and audited in isolation with zero risk to real users. The
//! [`persistence`] module maps it to row form and, via [`at_rest`] (Argon2id +
//! XChaCha20-Poly1305), seals it encrypted on disk; [`duress`] layers several
//! independently-keyed, indistinguishable compartments into one blob for coercion
//! resistance (decoy + real passphrases, panic wipe). The [`identity`] module
//! provides the on-device Ed25519 keys and BIP39 recovery, [`invite`] is the
//! invitation-only onboarding gateway (single-use, expiring, identity-free tokens), and
//! [`vouching`] is the ingestion boundary that verifies signed vouches/burns before they
//! reach the pure trust engine. The [`messaging`] module provides forward-secret 1:1
//! channels over the audited Olm Double Ratchet (`vodozemac`), and [`framing`] is the
//! metadata-resistance kernel of the transport: it pads every payload into a fixed-size block
//! (and can also seal it) so an untrusted relay sees only equal-sized opaque blobs. The
//! [`queue`] module is the SMP-style anonymous simplex-queue protocol — identity-free random
//! queues with recipient/sender capability separation and authenticated commands — with a
//! reference relay that enforces the rules; the [`transport`] module is the lower-level opaque
//! blob pipe a networked relay client (Tor) will implement. The [`group`] module provides
//! tier-gated small-group messaging over the audited Megolm group ratchet (`vodozemac`), with
//! key rotation on member removal.

#![forbid(unsafe_code)]

pub mod at_rest;
pub mod duress;
pub mod framing;
pub mod group;
pub mod identity;
pub mod invite;
pub mod messaging;
pub mod persistence;
pub mod queue;
pub mod transport;
pub mod trust;
pub mod vouching;
