# Threat Model & Safety Requirements

**Project:** A web of trust for LGBTQ+ people at risk
**Status:** Draft v0.1 — for review before any architecture is committed
**Audience:** Builders, reviewers, and human-rights/security partners

> This document deliberately leads with *who we protect users from* and *what happens
> when things go wrong*, because for this population those answers must drive every
> technical choice. No application can make a person fully safe. The goal is to
> minimise harm, avoid creating new dangers, and be honest about the limits.

---

## 1. Mission & scope

Build a tool that lets LGBTQ+ people — especially those isolated, fearful, or living
where homosexuality is criminalised — gradually establish trust with genuine peers and
then communicate, share files, exchange advice, and support one another, **without
exposing who or where they are**.

In scope: identity, trust establishment (the "web of trust"), messaging, file sharing,
resource sharing, optional mutual aid. Out of scope for v1: public discovery of
strangers (explicitly a non-goal — see §6), and on-platform money movement (deferred).

---

## 2. Assets to protect (what an adversary wants)

| # | Asset | Why it's sensitive | Worst-case harm |
|---|-------|--------------------|-----------------|
| A1 | **The fact a person uses the app at all** | Mere use implies LGBTQ+ identity | Arrest, outing, violence |
| A2 | **The social graph (who trusts/talks to whom)** | Maps an entire community from one node | Mass arrests, network roll-up |
| A3 | **Message & file content** | Direct evidence | Prosecution, blackmail |
| A4 | **Metadata (who, when, where, how often)** | Often enough to convict or target | Targeting, pattern-of-life |
| A5 | **Real-world identity / location** | Links pseudonym to person | Arrest, violence |
| A6 | **Trust/vouch records** | Reveal relationships and "who let whom in" | Network roll-up, retaliation against vouchers |
| A7 | **Funds / mutual-aid flows** | Money trails de-anonymise and are criminalised | Prosecution, asset seizure |
| A8 | **Recovery secrets / keys** | Compromise an identity | Impersonation, full account takeover |

**Highest-value targets:** A1, A2, A4. Content encryption (A3) is largely a solved
problem; the differentiator here is protecting *existence, relationships, and metadata*.

---

## 3. Adversaries (ordered by real-world lethality)

### ADV-1 — State / law enforcement (primary)
- **Capabilities:** ISP-level interception and DPI, compelled access to app stores and
  cloud providers, lawful-intercept orders, device seizure at checkpoints/raids,
  border phone searches, ability to run honeypot accounts, ability to block/throttle
  services, sometimes nation-state malware.
- **Goals:** Identify LGBTQ+ individuals; map and roll up networks; obtain evidence.
- **Notes:** May coerce a captured user to act against the network ("rubber-hose").

### ADV-2 — Infiltrators / entrappers
- **Capabilities:** Pose convincingly as gay peers; patient; seek to be vouched in,
  then enumerate and report members. Real precedent: police honeypots on dating apps
  have led to arrests (e.g. documented entrapment via Grindr in Egypt).
- **Goals:** Penetrate the trust graph; identify as many real members as possible.

### ADV-3 — Blackmailers / outers (incl. hostile family, community, employers)
- **Capabilities:** Social engineering, screenshots, stolen/borrowed devices,
  shoulder-surfing.
- **Goals:** Extort, shame, control, out the individual.

### ADV-4 — Passive mass surveillance
- **Capabilities:** Bulk metadata collection, traffic analysis, timing correlation.
- **Goals:** Discover *who is using the app* and *communication patterns* at scale.

### ADV-5 — The platform / operators / insiders (must be powerless to betray users)
- **Capabilities:** Server access, logs, ability to push malicious updates, subpoena
  exposure, rogue employee.
- **Goals:** (Assumed hostile for design purposes.) Whatever a breach or coercion enables.

### ADV-6 — Opportunistic thieves / non-targeted attackers
- **Capabilities:** Steal/find unlocked phone; commodity malware.
- **Goals:** Generic; but for this population even incidental access is dangerous.

---

## 4. Trust assumptions

- We trust the user's **own device only while unlocked and uncompromised** — and even
  that only weakly (assume it may be seized).
- We trust **audited, widely-reviewed cryptography and transports** (Signal protocol,
  Tor, vetted ZK libraries). We do **not** trust home-grown crypto.
- We do **not** trust any server, the app store, the network, or the operators with
  anything that could harm a user if exposed.
- We do **not** assume users are technical, well-resourced, or have safe connectivity.

---

## 5. Attack scenarios → required mitigations

Each scenario lists the adversary, the attack, and the mitigation that becomes a
requirement in §7.

| ID | Scenario | Adversary | Mitigation theme |
|----|----------|-----------|------------------|
| S1 | Phone seized at a checkpoint and inspected | ADV-1/3/6 | Disguise, hidden vault, duress PIN, no obvious app, no plaintext at rest |
| S2 | ISP/state sees the user connect to a known service | ADV-1/4 | Pluggable transports / bridges; traffic looks innocuous; mixnet/cover traffic |
| S3 | Infiltrator gets vouched in, then enumerates members | ADV-2 | Compartmentalised visibility (1-hop only); accountable vouching; trust tiers |
| S4 | Server is seized or subpoenaed | ADV-1/5 | No social graph server-side; opaque blobs only; no logs/metadata retained |
| S5 | Timing correlation links two users | ADV-1/4 | Metadata-resistant transport, batching/delay, cover traffic |
| S6 | A vouched member is captured and coerced | ADV-1 | Blast-radius limits; burn/revocation; disappearing content; no graph on device beyond 1 hop |
| S7 | Malicious app update ships a backdoor | ADV-1/5 | Reproducible builds, signed releases, optional out-of-store distribution, open source |
| S8 | Recovery flow leaks identity (phone/email) | ADV-1/3 | No PII anywhere; offline user-held recovery secret |
| S9 | Blackmailer borrows/steals unlocked phone | ADV-3/6 | Per-open auth, decoy mode, fast-hide, content expiry |
| S10 | Funds flow is traced to a person | ADV-1 | Defer; if ever built, privacy-preserving and opt-in with legal review |
| S11 | Sybil flood of fake members to map/disrupt | ADV-2 | Invitation-only growth; vouching cost; no stranger discovery |
| S12 | Push-notification / app-store identifiers de-anonymise | ADV-1/5 | Avoid push tokens tied to identity; no GCM/APNs PII; poll or P2P wake |

---

## 6. Explicit non-goals (safety by omission)

- **No discovery of strangers / no "find gay people near me."** This is the single
  biggest entrapment and mass-targeting vector and is deliberately excluded. Growth is
  by personal, out-of-band invitation only.
- **No global member directory or global trust graph**, on a server or a blockchain.
- **No real-world identity, phone number, or email — ever.**
- **No analytics, telemetry, crash reporting, or ad SDKs.**
- **No cloud backup of content or graph by default.**

---

## 7. Safety & privacy requirements (derived)

Requirements are labelled **MUST / SHOULD / LATER**. These are the acceptance criteria
the architecture in the next phase will be judged against.

### 7.1 Identity & recovery
- **MUST** use on-device keypairs; no PII collected anywhere.
- **MUST** allow a human-friendly pseudonym only; no uniqueness enforced via PII.
- **MUST** make recovery depend on a user-held offline secret (passphrase/paper), never
  a phone/email/server.
- **SHOULD** support multiple identities / compartments on one device.

### 7.2 Trust establishment (the web of trust)
- **MUST** be **invitation-only** (in-person QR or single-use expiring invite over an
  existing trusted channel).
- **MUST** enforce **1-hop visibility**: a user can see only their direct contacts,
  never the broader graph.
- **MUST** make vouching **accountable** (vouching for a later-burned contact lowers the
  voucher's standing) and **revocable**.
- **MUST** gate capabilities by **trust tier / depth** (see plan §6).
- **MUST** support **burn/revocation** that warns 1-hop neighbours locally without a
  global broadcast.
- **SHOULD** compute all trust scores **locally**, from only the data the user can see.

### 7.3 Confidentiality & integrity
- **MUST** use audited E2EE with forward secrecy and post-compromise security (Signal
  protocol or equivalent).
- **MUST** default to **disappearing messages/files**.
- **MUST** encrypt all data at rest on the device under a key derived from user auth.
- **MUST NOT** roll its own cryptography.

### 7.4 Metadata resistance
- **MUST** support a **censorship-resistant, metadata-minimising transport** (e.g.
  Tor + pluggable transports/bridges, P2P, and/or a mixnet such as Nym).
- **MUST NOT** require identity-linked push tokens (no APNs/FCM PII).
- **SHOULD** use batching/delay and cover traffic to resist timing correlation.
- **SHOULD** make traffic resemble innocuous/common traffic.

### 7.5 Server & operator powerlessness
- **MUST** ensure any server stores only opaque, content-free blobs with no social graph
  and no retained metadata/logs.
- **MUST** be designed so a full server compromise cannot reveal A1–A6.
- **SHOULD** prefer P2P / no-server where feasible (server only as a relay/store-forward).

### 7.6 Device-loss & coercion resilience
- **MUST** require authentication on every open (PIN/passphrase/biometric-with-fallback).
- **MUST** provide a **duress mechanism** (decoy view and/or panic wipe).
- **SHOULD** provide app **disguise** (innocuous name/icon) and fast-hide.
- **SHOULD** keep no more graph data on-device than the 1-hop horizon requires.

### 7.7 Supply chain & distribution
- **MUST** be open source and independently auditable.
- **MUST** ship signed, **reproducible builds**.
- **SHOULD** offer out-of-app-store distribution (e.g. verified APK, F-Droid-style) for
  regions where stores are coerced or blocked.

### 7.8 Usability as a safety property
- **MUST** be usable by non-technical, frightened users on cheap Android and poor
  connectivity; safety defaults on; no crypto jargon in the UI.
- **MUST** include honest, in-app guidance on what the app can and cannot protect.
- **SHOULD** be fully localisable and support low-literacy / icon-driven flows.

### 7.9 Process & governance
- **MUST** complete an independent security & privacy audit before any at-risk user
  onboards.
- **MUST** partner with experienced digital-rights / LGBTQ human-rights technologists.
- **MUST** maintain a coordinated vulnerability-disclosure and incident process.
- **SHOULD** obtain legal review per target jurisdiction, especially before any funds
  feature.

---

## 8. Residual risks (we cannot fully eliminate)

- **Device seizure while unlocked**, or **rubber-hose coercion** of a captured user.
- **Endpoint compromise** (nation-state malware) defeats any app-level protection.
- **Human error and social engineering** (a user vouching for an infiltrator, screenshots).
- **Traffic-analysis at nation-state scale** is mitigated, not eliminated.
- **The app's mere presence**, if discovered, may itself be incriminating (hence disguise).

These residual risks make honest user education and conservative defaults mandatory.

---

## 9. How this threat model decides the foundation

The threat model favours, in order:

1. **No global graph / no global registry** (A2, S3, S4, S6, S11) → argues **against** a
   global blockchain or server-side membership set as the *foundation*.
2. **Metadata resistance and censorship circumvention** (A1, A4, S2, S5) → argues for a
   **local-first, Tor/mixnet-capable transport**.
3. **Operator powerlessness** (ADV-5, S4) → argues for **P2P / no-trusted-server**.
4. **Low friction for non-technical, poor users** (7.8) → argues **against** wallet/
   proof/gas friction at the core.

**Implication:** a **local-first, invitation-only, compartmentalised** foundation
(the model proven by Briar / SimpleX) best satisfies the threat model. A zero-knowledge
credential layer (Semaphore-style, or the patterns in this repo's demo) is valuable but
should be **optional and scoped to small per-community features** (anonymous vouch/vote,
later mutual aid) — never the holder of the global social graph. A general-purpose
blockchain foundation is **not recommended** because a durable, global ledger of
trust/membership events is precisely the artifact this population cannot afford.

This resolves the open "foundation" question toward **Option A + optional B**, on
threat-model grounds rather than technology preference.

---

## 10. Open questions for partners/review

1. Which target regions/jurisdictions first? (Drives transport, language, legal review.)
2. Acceptable level of P2P-only vs. relay-assisted (affects deliverability when peers are offline).
3. Is any funds/mutual-aid feature in scope at all, given legal exposure?
4. Distribution strategy where app stores are coerced or blocked?
5. Who are the human-rights/security review partners, and what is the audit timeline?
