//! Networked edges implementing [`lattice_core::queue::Relay`] (roadmap 1.3 remainder).
//!
//! `lattice-core::queue` is the pure, offline protocol kernel: the command codec, the
//! per-queue key model, and the rules a relay must enforce, all tested against an in-process
//! [`InMemoryRelay`](lattice_core::queue::InMemoryRelay). This crate is the thin edge that
//! ships those exact signed commands over an actual network connection to a real relay
//! (`lattice-relay`) — the one piece needing live network I/O, deliberately kept out of
//! `lattice-core` so that crate's build stays pure, no-network, and portable to every target
//! (`7.5`).
//!
//! [`tor::TorRelayClient`] is the production path: every command dials out over a fresh,
//! isolated Tor circuit, so the relay never learns the caller's real address. [`plain`] is a
//! development/test-only stand-in with no Tor circuit, for exercising the wire protocol and
//! `lattice-relay` locally.

pub mod plain;
pub mod tor;
mod wire;
