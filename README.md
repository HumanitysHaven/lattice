# lattice

A **local-first web of trust** for people who need to find and trust each other safely —
built first for LGBTQ+ people who are isolated, fearful, or living where being gay is
criminalised, and useful to anyone who needs private, trust-gated community.

> `lattice` is a working codename and should be replaced with a deliberately
> unremarkable name before any release. Disguise is a design requirement, not an
> afterthought (see `docs/threat-model.md` §7.6).

## What this is

- **Local-first.** All keys, data, the social graph, and trust computation live and run
  **on the user's own device**. There is no server that holds user data or runs client
  logic. Untrusted relays may carry opaque, fixed-size encrypted blobs for delivery, but
  can never read content, identify users, or link who talks to whom.
- **Invitation-only.** Growth happens by personal, out-of-band invitation (in-person QR
  or one-time link). There is deliberately **no discovery of strangers** — that is the
  single biggest entrapment vector and is excluded by design.
- **Compartmentalised.** A user only ever sees their **1-hop** neighbourhood. A single
  compromised device cannot enumerate the wider network.
- **Built from proven, audited components only.** No home-grown cryptography.

## Documents (read these first)

- [`docs/threat-model.md`](docs/threat-model.md) — who we protect users from, attack
  scenarios, and the derived MUST/SHOULD requirements. **This is the source of truth.**
- [`docs/technical-spec.md`](docs/technical-spec.md) — how the system meets those
  requirements: stack, identity model, data model, trust algorithm, protocols, MVP.
- [`docs/architecture-overview.md`](docs/architecture-overview.md) — the high-level design
  and the options considered.

## Repository layout

```
core/          Rust security-critical library (identity, trust, crypto, transport).
                Compiles to Android/iOS/desktop/wasm. Pure, no network I/O, no unsafe code.
relay-client/   Networked edge: implements core's queue::Relay trait over Tor (arti-client).
relay/          Reference relay server: enforces core's queue protocol, reachable over the
                network. Kept out of core/ so core's build stays pure and portable.
app/            (planned) Flutter UI shell over the core via FFI.
docs/           Threat model, technical spec, architecture, roadmap.
```

## Current status

The safety-critical core — trust engine, identity, encrypted-at-rest storage, the duress
vault, invitation onboarding, forward-secret 1:1 (Olm) and small-group (Megolm) messaging,
and the authenticated anonymous-queue transport protocol — is implemented and tested, along
with a networked relay client/server pair over Tor. See
[`docs/roadmap.md`](docs/roadmap.md) for the up-to-date milestone-by-milestone status; it is
the source of truth for "what's actually done" over this file.

### Build & test

```bash
cargo test --workspace
```

## Planned technology (see the spec for rationale)

- **Rust core** + **Flutter** UI (one auditable codebase, broad cheap-device reach).
- **libsignal** (Double Ratchet) for 1:1; **OpenMLS** (RFC 9420) for groups.
- **SimpleX SMP**-style anonymous message queues over **Tor** for metadata-resistant,
  relay-assisted delivery.
- **SQLCipher** + Argon2id for encrypted-at-rest storage with deniable duress vaults.
- *(Optional, per-community only)* **Semaphore** zero-knowledge proofs for anonymous
  vouch/vote — never a global registry.

## Safety note

No software can make a person fully safe against device seizure, coercion, or endpoint
compromise. This project aims to minimise harm, avoid creating new dangers, and be honest
about its limits. It must receive an independent security and privacy audit, and be
reviewed with experienced human-rights technologists, **before any at-risk user onboards.**

## License

[AGPL-3.0-only](LICENSE).
