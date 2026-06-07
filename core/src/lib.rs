//! `lattice-core` — the security-critical core for a local-first web of trust
//! designed for at-risk communities.
//!
//! Everything in this crate runs **on the user's own device**. There is no server
//! component here and no module may introduce one: the design's safety rests on the
//! fact that the operator/network is powerless (see `docs/threat-model.md` req `7.5`).
//!
//! The [`trust`] engine is the first fully-implemented module: it is pure and offline and
//! can be developed and audited in isolation with zero risk to real users. The
//! [`persistence`] module maps it to the encrypted local store. The [`identity`],
//! [`messaging`], and [`transport`] modules are typed scaffolds that pin down the
//! architecture; their concrete implementations wrap audited upstream libraries and land
//! in later milestones (see `docs/roadmap.md`).

#![forbid(unsafe_code)]

pub mod identity;
pub mod messaging;
pub mod persistence;
pub mod transport;
pub mod trust;
