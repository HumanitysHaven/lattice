# Roadmap & Milestones

**Project:** A web of trust for LGBTQ+ people at risk (codename `lattice`)
**Status:** Draft v0.1
**Companion docs:** [`threat-model.md`](threat-model.md), [`technical-spec.md`](technical-spec.md), [`architecture-overview.md`](architecture-overview.md)

This roadmap sequences the build so that **safety-critical, low-risk work comes first**
and **nothing touches a real at-risk user until it has been independently audited**. Each
milestone lists its exit criteria as testable conditions tied to threat-model requirements.

> Guiding rule: we never ship a capability whose failure mode is "a user gets outed or
> arrested" before that capability has been red-teamed and audited.

---

## Phase 0 — Foundations (no real users) — *in progress*

| # | Milestone | Exit criteria |
|---|-----------|---------------|
| 0.1 | Threat model & safety requirements | `threat-model.md` reviewed by an external human-rights/security partner |
| 0.2 | Technical spec & architecture | `technical-spec.md` + `architecture-overview.md` reviewed; stack confirmed |
| 0.3 | **Trust engine (pure, offline)** ✅ scaffolded | `cargo test` green; covers tiers, decay, burn, Sybil-cluster independence, revocation |
| 0.4 | Persistence mapping ✅ scaffolded | Row **and whole-graph** snapshot/restore round-trip green; schema scoped to the pure engine's state with §4's crypto/identity columns documented as deferred to their owning layers; no DB engine yet |
| 0.5 | Module scaffolds (identity/messaging/transport) ✅ | Typed stubs compile; architecture visible end-to-end |

**Phase 0 done when:** the three docs are partner-reviewed and the core crate builds with
a green test suite and clean clippy.

---

## Phase 1 — Local MVP: trust engine + safe messaging (closed alpha, trusted testers only)

Delivers the spec's MVP (§11). **Not for at-risk users yet** — only for the team and
vetted technical reviewers using throwaway data.

| # | Milestone | Exit criteria |
|---|-----------|---------------|
| 1.1 | Identity & recovery | Real Ed25519 signing identity ✅ + 24-word BIP39 recovery restores the same identity ✅ + sign/verify ✅; no PII anywhere ✅ (`7.1`). libsignal Double-Ratchet identity key deferred to 1.4 (reuses the same seed) |
| 1.2 | Encrypted local store | Done ✅ (pure-Rust at-rest vault instead of SQLCipher): Argon2id-derived key + XChaCha20-Poly1305 AEAD seal of the serialized store via `at_rest`/`persistence::seal_graph`; header (incl. KDF params) authenticated; untrusted KDF params bounded; nothing plaintext at rest, wrong passphrase/tamper rejected (`7.3`). Note: deviates from spec's SQLCipher choice to keep the core pure/hermetic; a queryable encrypted DB can layer over the same key later. Duress/decoy vault is 1.8 |
| 1.3 | Anonymous-queue transport | Done ✅. (a) `framing`: every payload is padded into a fixed-size block (and optionally AEAD-sealed) so all blobs are equal-sized — a relay sees no length signal. (b) `queue`: the SMP-style **authenticated simplex-queue protocol** — identity-free random recipient/sender queue ids, recipient/sender **capability separation** (a contact who can write cannot read, and never learns the recipient id), Ed25519-signed domain-separated commands, plus a reference `InMemoryRelay` that enforces it all; verified end-to-end (Olm message delivered through an authenticated queue; relay holds only opaque equal-sized blobs). (c) Networked relay edges: the workspace has `relay` (a small binary — `InMemoryRelay` behind a length-prefixed TCP listener, shared across connections, no plaintext ever held) and `relay-client` (implements `queue::Relay` over the network) with two transports — `plain::PlainTcpRelayClient` (dev/test only, no anonymity) and `tor::TorRelayClient` (production: `arti-client`, the Tor Project's own pure-Rust client, `static-sqlite` + `rustls` so no system Tor/OpenSSL dependency; every command dials a fresh **isolated Tor circuit**, a superset of "per-queue" unlinkability). **Fully verified end-to-end** ✅ (2026-08-18): the wire protocol over real loopback TCP (`relay-client/tests/plain_relay.rs`), live Tor bootstrap on a real machine (`tor_bootstrap_smoke_test`), and the complete path — create/send/receive round-tripped byte-for-byte through a `lattice-relay` deployed on a real routable host, reached over three independent live Tor circuits (`tor_relay_round_trip`). Remaining: decide whether `lattice-relay` itself should also be reachable as a Tor onion service (currently clearnet-listener-only — clients dial it via Tor, but the relay's own address isn't hidden), and adversarial-relay unlinkability instrumentation (`7.4`, `S5`) |
| 1.4 | 1:1 messaging | Done ✅ (`messaging`): forward-secret 1:1 channels over the audited Olm Double Ratchet (`vodozemac`), with pre-key handshake, ratchet advance, out-of-order tolerance, and disappearing TTL carried **inside** the encrypted payload (`7.3`). Wire = `type ‖ olm-ciphertext`, padded to a fixed block (`framing::pad`) so the relay sees equal-sized opaque blobs. **Deviation:** spec named libsignal, which is not consumable as a hermetic Rust crate (git-only, AGPL, BoringSSL); vodozemac is the audited (Least Authority), pure-Rust, crates.io Double Ratchet and also gives us Megolm for 1.7. Remaining: bind the Olm handshake to the verified invite/identity, and derive the Olm account from the same on-device seed as the signing identity |
| 1.5 | Invitation onboarding | Core lifecycle done ✅: single-use, expiring, identity-free invite tokens (`invite`) with authoritative issuer-side validation, encode/decode for QR/link, and Tier-0 onboarding; no stranger discovery exists. Remaining: carry redemption over the anonymous-queue handshake (1.3/1.4) and QR/link UI (`7.2`, `S11`) |
| 1.6 | Trust engine integrated | Core ingestion done ✅: signed vouches/burns (`vouching`) are signature-verified at the boundary, then drive score/tier/burn in the engine. Remaining: wire to real in-app capability gating once UI exists (`7.2`) |
| 1.7 | Small-group chat | Done ✅ (`group`, `core/tests/group_choreography.rs`): tier-gated small-group E2EE over the audited **Megolm** group ratchet (`vodozemac`). Each member has one outbound sender ratchet + an inbound ratchet per other member; a message is encrypted once and fanned out. `add_member` enforces the Tier-1+ (`group_chat`) gate; `remove_member` **rotates** the outbound ratchet so the removed member loses access (post-compromise security), and a later-added member can't read prior history (forward secrecy on join). Disappearing TTL rides inside the payload as in 1:1; sender keys distribute over the 1:1 channels (1.4) and ciphertext pads (`framing`) onto the queue (1.3) — an integration test now proves this choreography end-to-end through the public API (real Olm sessions + real queues, not the in-memory shortcut `group.rs`'s own unit tests use): key distribution, fan-out, and on removal, rotation plus redistribution to the members who remain. **Deviation:** spec named OpenMLS (RFC 9420); Megolm gives the same group-E2EE shape for the MVP from the crate we already depend on and is independently audited, keeping the build pure/hermetic — MLS's tree-based CGKA is a worthwhile later upgrade for large/dynamic groups (`7.3`) |
| 1.8 | Coercion & disguise | Core deniable vault done ✅ (`duress`): multiple independently-keyed, indistinguishable compartments in one blob (decoy + real passphrases), Argon2id + XChaCha20-Poly1305 reusing the audited `at_rest` primitives; constant blob size and constant-work `open` so the count of real compartments is unprovable; panic wipe (`wipe_slot`/`wipe_all`) leaves a slot indistinguishable from never-used; auth-on-open intrinsic (`7.6`, `S1`, `S9`). Remaining: app disguise (alt icon/name) + panic-gesture wiring land with the UI |

**Phase 1 done when:** all MVP MUST requirements in `threat-model.md` §7 pass the §12 test
plan, including the adversarial-relay metadata tests and duress-vault indistinguishability.

---

## Phase 2 — Community & resilience (security audit gate before any at-risk user)

| # | Milestone | Exit criteria |
|---|-----------|---------------|
| 2.1 | **Independent security & privacy audit #1** | Findings remediated; report published (`7.9`) |
| 2.2 | Trust-gated community spaces | Tier-gated larger groups; admin (Tier 3) curates joins |
| 2.3 | Signed resource sharing | Provenance-tracked legal/safe-house/mental-health/VPN guides propagate through the graph |
| 2.4 | E2EE file sharing | Chunked, expiring, size-limited transfers (`7.3`) |
| 2.5 | Localisation & low-literacy UX | Multiple languages; icon-driven flows; cheap-Android performance (`7.8`) |
| 2.6 | Out-of-store distribution | Reproducible signed builds; verified APK / F-Droid-style channel (`7.7`, `S7`) |
| 2.7 | Censorship resilience | Pluggable transports/bridges; works where the network is hostile (`S2`) |

**Phase 2 done when:** audit #1 is remediated **and** a controlled pilot with a partner
organisation (not the open public) validates real-world usability and safety.

---

## Phase 3 — Optional advanced capabilities (only with strong justification + review)

| # | Milestone | Exit criteria |
|---|-----------|---------------|
| 3.1 | Per-community zk layer | Semaphore group *scoped to a community*; anonymous vouch/vote with nullifiers; never a global registry (spec §10) |
| 3.2 | zk-based revocation | Prove a community credential isn't burned (sparse-Merkle non-membership pattern) |
| 3.3 | Cover traffic & timing hardening | Tunable cover traffic; measured resistance to timing correlation (`S5`) |
| 3.4 | Multi-device | Optional, without weakening metadata or recovery guarantees |
| 3.5 | **Mutual-aid funds — DEFERRED pending legal review** | Per-jurisdiction legal counsel; privacy-preserving, opt-in only (`S10`) |

**Phase 3 items are individually gated:** each requires its own threat-model delta and,
where it touches money or new metadata, its own audit and legal sign-off.

---

## Cross-cutting, every phase

- **Security review** of each merged capability; red-team the invite/vouch flow for
  infiltration (`S3`, `S11`) on an ongoing basis.
- **Reproducible builds** and signed releases from day one (`7.7`).
- **No analytics/telemetry** ever (non-goal §6 of the threat model).
- **Honest user guidance** kept current on what the app can and cannot protect.
- **Partner & community involvement** — affected people and human-rights technologists in
  the loop throughout, not just at the end.

---

## Progress snapshot

The safety-critical core is implemented and tested in isolation: the trust engine (0.3),
persistence + encryption at rest (0.4 / 1.2), identity & recovery (1.1), signed vouches/burns
(1.6 ingestion), invitation onboarding (1.5 lifecycle), the duress / deniable vault (1.8
core), the transport framing kernel + authenticated simplex-queue protocol (1.3 core),
forward-secret 1:1 messaging over the Olm Double Ratchet (1.4), and tier-gated small-group
chat over the Megolm group ratchet, including membership-change choreography over real
sessions and queues (1.7, done). Two end-to-end integration harnesses
(`core/tests/end_to_end.rs`, `core/tests/group_choreography.rs`) compose these through the
public API against the reference untrusted relay and assert the emergent properties
(forward-secret delivery over an authenticated queue, equal-sized opaque blobs even for the
handshake, no plaintext at the relay, write-only senders that cannot read, vouch-driven
capability unlocks, and — for groups — real key distribution, fan-out, and rotation-on-removal
that locks a removed member out).

The repo is now a Cargo workspace: `core` stays the pure, no-network library described above,
and two new networked edges implement 1.3's remaining piece — `relay` (a reference server)
and `relay-client` (implements `queue::Relay` over the network, with a Tor transport for
production and a plain-TCP one for dev/test). As of 2026-08-18 this path is confirmed working
for real: a `lattice-relay` deployed on a routable host, reached from a separate machine over
three independent live Tor circuits, round-tripped a message byte-for-byte. **1.3 is done.**

Every Phase 1 milestone now has its core logic implemented and tested; what's left is either
UI-dependent (1.5's QR/link flow, 1.8's app disguise — both wait on the Flutter shell) or the
two hardening items called out below (unlinkability instrumentation, MLS-for-scale).

## Immediate next actions

1. Get `threat-model.md` and `technical-spec.md` in front of an external reviewer (0.1/0.2).
2. Decide the remaining open engineering questions in `technical-spec.md` §13
   (Flutter-over-Rust FFI vs. native screens; offline/store-and-forward retention window).
   §13's relay questions are now effectively settled by what's built: a custom Rust protocol
   (not literal SimpleX SDK integration) against a relay we run ourselves.
3. Add adversarial-relay unlinkability instrumentation for the queue transport (`7.4`, `S5`) —
   the remaining hardening item now that the networked path itself is confirmed working.
4. Decide whether `lattice-relay` should also run as a Tor onion service (see 1.3).
5. Evaluate an MLS (RFC 9420) upgrade for groups once they need to scale beyond the small,
   fully-connected shape Megolm suits.
4. Decide whether `lattice-relay` should itself be reachable as a Tor onion service (hides the
   relay operator's address too) or clearnet-plus-Tor-dial is sufficient for the threat model.
5. Evaluate an MLS (RFC 9420) upgrade for groups once they need to scale beyond the small,
   fully-connected shape Megolm suits.
