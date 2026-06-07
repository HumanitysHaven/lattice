# Architecture Overview

**Project:** A web of trust for LGBTQ+ people at risk (codename `lattice`)
**Status:** Draft v0.1 — high-level design and the options considered
**Companion docs:** [`threat-model.md`](threat-model.md), [`technical-spec.md`](technical-spec.md)

This is the orientation document. The threat model is the source of truth for *what we
must achieve*; the technical spec is *how*. This overview explains the shape of the
problem and why the chosen architecture beats the alternatives.

---

## 1. The problem, reframed

"Web of trust" usually means a global graph of cryptographic vouches (like PGP). For
**fearful, isolated, possibly-surveilled people in countries where being gay is
criminalised**, the real problem splits in two:

1. **Trust establishment** — how does a frightened, isolated person come to believe a
   stranger is a *genuine safe peer* and not police, a blackmailer, or an infiltrator?
2. **Safe capability** — once some trust exists, how do they communicate, share files,
   advice, and support **without leaving a trail** that could get them imprisoned, outed,
   or killed?

Content encryption is largely solved. The hard, safety-critical work is trust
establishment plus **metadata protection**.

## 2. Threat model in one paragraph

We protect users from (in order of lethality): **state/police** (interception, device
seizure, honeypots), **infiltrators/entrappers** (pose as peers, get vouched in, then map
and report the network), **blackmailers/outers**, **mass surveillance**, and **the
platform/operators themselves** (assumed hostile). The highest-value targets are the
*fact someone uses the app*, the *social graph*, and *metadata* — not just message
content. Full detail in [`threat-model.md`](threat-model.md).

## 3. Design principles

- **Local-first / friend-to-friend** — the device holds all truth; no one holds the
  global graph.
- **No phone number, email, or real name — ever.**
- **Metadata resistance first** — hiding *who talks to whom and when* matters more than
  message encryption.
- **Plausible deniability** — disguise, hidden vaults, duress mode.
- **Trust is earned gradually and is revocable.**
- **Cannot betray users under compromise** — a fully breached server reveals nothing.
- **Easy for a scared, non-technical, low-resource person.**

## 4. The hard part: infiltration & Sybil resistance

A naive web of trust fails dangerously — police walk in. Mitigations baked into the
design:

- **Compartmentalised visibility:** a member sees only their **1-hop** neighbours. A
  compromised node exposes only its handful of direct contacts.
- **Accountable vouching:** vouching for someone later "burned" damages the voucher's own
  standing (skin in the game).
- **Capabilities gated by trust depth** (tiers).
- **Local burn/revocation** warns neighbours without a global broadcast.
- **No stranger discovery.** Growth is by personal invitation only — this removes the
  largest entrapment vector.

## 5. Architecture options considered

| Option | Summary | Verdict |
|--------|---------|---------|
| **A. Local-first F2F** (Briar/SimpleX-style), invitation-based trust, no blockchain | Strongest real-world safety; no honeypot; works under censorship/offline; free; no crypto/wallet friction | **Foundation** |
| **B. Anonymous-credential layer** (Semaphore-style / this project's nullifier+Merkle pattern) | Unlocks *anonymous* community actions (vouch/vote/fund access) without identity | **Optional, per-community only** |
| **C. Full blockchain foundation** (e.g. Midnight) | Strong on-chain privacy primitives, but a durable global ledger of trust events is exactly the artifact this population can't afford; high friction/cost; metadata still leaks without a mixnet | **Not the foundation** |

**Why A over C:** the threat model demands *no global graph/registry*, *metadata
resistance*, *operator powerlessness*, and *low friction*. A satisfies all four; a global
blockchain registry actively works against the first.

```
┌─────────────────────────────────────────────┐
│  Local-first app (mobile-first, disguisable) │
├─────────────────────────────────────────────┤
│  Trust engine (local): invites, vouching,    │  ← the "web of trust"
│  decaying trust scores, revocation/burn      │
├─────────────────────────────────────────────┤
│  Capabilities: 1:1 & group chat, file share, │  ← unlocked by trust depth
│  advice/resources, (later) pooled funds      │
├─────────────────────────────────────────────┤
│  Transport: E2EE + metadata resistance       │  ← anonymous queues over Tor
├─────────────────────────────────────────────┤
│  OPTIONAL zk layer (Semaphore) per-community │  ← anonymous vouch/vote only
└─────────────────────────────────────────────┘
```

## 6. How trust works (mechanics)

- **Identity:** on-device keypair + a local nickname; no PII; offline recovery phrase.
- **Joining:** invitation only (in-person QR or one-time expiring link).
- **Vouching:** signed, weighted, accountable, revocable.
- **Trust score:** computed locally from the vouch paths you can see, decaying with age,
  rising with independent vouches, strongly reduced by credible burn signals.
- **Tiers unlock capabilities:** invited → 1:1 chat; vouched → groups/resources; trusted →
  file sharing/larger communities; core → hosting and (later) pooled funds.

## 7. Capabilities unlocked

Messaging (1:1 + groups, disappearing by default), expiring E2EE file sharing, signed
**safe-resource** sharing (legal/safe-house/mental-health/VPN guides), trust-gated
community spaces, and — deferred pending legal review — mutual-aid funds.

## 8. UX for scared, non-technical, low-resource users

Mobile-first on cheap Android; tiny, offline-capable; **no crypto jargon**; safety
defaults on; disguise + duress/panic features; localisation and icon-driven flows; honest
in-app guidance on what the app can and cannot protect.

## 9. What we reuse from the original demo

The sibling Midnight ZK demo's **nullifier + Merkle membership** pattern is a clean
template for *per-community* anonymous actions, and its **sparse-Merkle non-membership**
work suits **revocation** (prove a credential isn't burned). We port the *patterns* to the
more mature, audited **Semaphore** stack if/when the optional zk layer is built — never as
a global registry.

## 10. Phased roadmap

- **Phase 0 — Threat modeling & partners** (done as a draft; needs partner/audit review).
- **Phase 1 — MVP:** invitation-only onboarding, 1:1 + small-group E2EE chat over a
  metadata-resistant transport, the local trust/vouch engine, burn/revocation, disguise +
  duress. *(The trust engine is implemented first, in isolation — see `core/src/trust.rs`.)*
- **Phase 2 — Community features:** trust-gated groups, signed resources, file sharing,
  localisation.
- **Phase 3 — Optional zk layer; later, mutual-aid funds (with legal input).**
- **Throughout:** independent security & privacy audits before any at-risk user onboards.

## 11. Honest caveats

No app makes this fully safe (device seizure, coercion, endpoint malware can defeat any
design). We never roll our own crypto. Funds carry legal exposure and need counsel. Real
lives are at stake — partner with experienced human-rights technologists and audit before
launch.
