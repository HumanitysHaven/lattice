//! Local trust engine — the "web of trust" core.
//!
//! This module is intentionally **pure and offline**: it has no network, no I/O,
//! and no knowledge of cryptography or transport. It operates only on the data a
//! user can legitimately see — their **1-hop neighbourhood** — which is the central
//! safety property from `docs/threat-model.md` (req `7.2`, scenario `S3`): a single
//! compromised node can never enumerate the wider graph.
//!
//! Scoring follows `docs/technical-spec.md` §6. Trust is **safety-biased**: a single
//! credible "this contact is compromised" (burn) signal outweighs several vouches,
//! because a false "unsafe" is far cheaper than a false "safe" for this population.
//!
//! NOTE: parameters here are placeholders to be tuned with human-rights/security
//! partners; the structure, not the constants, is what this stub pins down.

use std::collections::{HashMap, HashSet};

/// A purely local, non-networkable handle for a contact. It is never sent over the
/// wire and cannot be used to address or discover the contact (req `7.1`).
pub type ContactId = [u8; 16];

/// How a contact entered the user's neighbourhood.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddedVia {
    /// Redeemed a one-time invite the user issued (in-person QR / one-time link).
    Invite,
    /// Introduced/vouched by an existing contact.
    VouchedIntro,
}

/// Lifecycle status of a contact.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Active,
    Paused,
    /// Flagged as compromised; contributes nothing and is excluded as a voucher.
    Burned,
}

/// Capability tiers. Discriminants ascend so ordering is meaningful.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Tier {
    /// Tier 0: 1:1 chat with the inviter only.
    Invited = 0,
    /// Tier 1: small group chat; receive signed resources.
    Vouched = 1,
    /// Tier 2: file sharing; larger communities.
    Trusted = 2,
    /// Tier 3: host a community; (LATER) pooled-fund participation.
    Core = 3,
}

/// Capability flags unlocked at a given tier (spec §6).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Capabilities {
    pub direct_message: bool,
    pub group_chat: bool,
    pub receive_resources: bool,
    pub file_sharing: bool,
    pub host_community: bool,
}

impl Tier {
    pub fn capabilities(self) -> Capabilities {
        Capabilities {
            direct_message: true,
            group_chat: self >= Tier::Vouched,
            receive_resources: self >= Tier::Vouched,
            file_sharing: self >= Tier::Trusted,
            host_community: self >= Tier::Core,
        }
    }
}

/// A direct (1-hop) contact. We never store a contact's own contacts.
#[derive(Clone, Debug)]
pub struct Contact {
    pub id: ContactId,
    pub added_via: AddedVia,
    pub status: Status,
    /// Cached, derived tier. Used as the basis for `voucher_trust` of *this* contact when
    /// it vouches for someone else. Caching (rather than recursing) is what keeps the
    /// computation strictly 1-hop and prevents traversing the wider graph (`S3`).
    pub tier: Tier,
    /// An optional **trust anchor** the user sets directly — e.g. someone they met and
    /// verified in person. It is a *floor*: the contact's effective tier never falls below
    /// it through ordinary recomputation, which is what lets a small set of personally
    /// trusted anchors bootstrap the web of trust (without an anchor, derived-only tiers
    /// have nothing to build on). A **burn always overrides the anchor** — safety wins.
    pub manual_floor: Option<Tier>,
}

impl Contact {
    pub fn new(id: ContactId, added_via: AddedVia) -> Self {
        Self { id, added_via, status: Status::Active, tier: Tier::Invited, manual_floor: None }
    }

    /// Builder: anchor this contact at a tier floor (a directly, personally trusted peer).
    pub fn with_manual_floor(mut self, floor: Tier) -> Self {
        self.manual_floor = Some(floor);
        self
    }
}

/// A signed introduction: one of my contacts vouches for another of my contacts.
#[derive(Clone, Debug)]
pub struct Vouch {
    pub subject: ContactId,
    pub voucher: ContactId,
    /// Voucher-asserted confidence, 1..=3.
    pub weight: u8,
    /// Unix seconds.
    pub created_at: i64,
    pub revoked: bool,
}

/// A local "this contact is compromised" signal received from a 1-hop neighbour.
#[derive(Clone, Debug)]
pub struct BurnSignal {
    pub subject: ContactId,
    pub origin: ContactId,
    pub created_at: i64,
}

/// Tunable scoring policy (spec §6). Defaults are placeholders.
#[derive(Clone, Copy, Debug)]
pub struct TrustParams {
    pub invite_base: f64,
    pub vouched_intro_base: f64,
    /// Multiplier applied to each burn signal — > 1 so one credible burn dominates.
    pub burn_coefficient: f64,
    /// Vouch weight half-life in days (older vouches count for less).
    pub half_life_days: f64,
    pub t1_threshold: f64,
    pub t2_threshold: f64,
    pub t3_threshold: f64,
}

impl Default for TrustParams {
    fn default() -> Self {
        Self {
            invite_base: 0.20,
            vouched_intro_base: 0.0,
            burn_coefficient: 1.5,
            half_life_days: 180.0,
            t1_threshold: 0.30,
            t2_threshold: 0.55,
            t3_threshold: 0.80,
        }
    }
}

/// Map a voucher's cached tier to how much its vouch is worth (`voucher_trust`).
fn tier_weight(tier: Tier) -> f64 {
    match tier {
        Tier::Invited => 0.2,
        Tier::Vouched => 0.5,
        Tier::Trusted => 0.8,
        Tier::Core => 1.0,
    }
}

/// The user's own local view of their 1-hop neighbourhood.
#[derive(Default)]
pub struct TrustGraph {
    contacts: HashMap<ContactId, Contact>,
    vouches: Vec<Vouch>,
    burns: Vec<BurnSignal>,
    params: TrustParams,
}

impl TrustGraph {
    pub fn new(params: TrustParams) -> Self {
        Self { params, ..Default::default() }
    }

    pub fn upsert_contact(&mut self, contact: Contact) {
        self.contacts.insert(contact.id, contact);
    }

    pub fn set_status(&mut self, id: &ContactId, status: Status) {
        if let Some(c) = self.contacts.get_mut(id) {
            c.status = status;
        }
    }

    pub fn add_vouch(&mut self, vouch: Vouch) {
        self.vouches.push(vouch);
    }

    /// Revoke every vouch where `voucher` vouched for `subject`. Returns how many were
    /// affected. Used when a contact retracts an introduction.
    pub fn revoke_vouch(&mut self, subject: &ContactId, voucher: &ContactId) -> usize {
        let mut n = 0;
        for v in self.vouches.iter_mut() {
            if &v.subject == subject && &v.voucher == voucher && !v.revoked {
                v.revoked = true;
                n += 1;
            }
        }
        n
    }

    /// Revoke all outgoing vouches made by `voucher` (e.g. when they ask to withdraw, or
    /// as a consequence of being burned). Returns how many were affected.
    pub fn revoke_vouches_by(&mut self, voucher: &ContactId) -> usize {
        let mut n = 0;
        for v in self.vouches.iter_mut() {
            if &v.voucher == voucher && !v.revoked {
                v.revoked = true;
                n += 1;
            }
        }
        n
    }

    pub fn add_burn(&mut self, burn: BurnSignal) {
        self.burns.push(burn);
    }

    pub fn contact(&self, id: &ContactId) -> Option<&Contact> {
        self.contacts.get(id)
    }

    /// Set (or clear) a contact's trust-anchor floor. Does not recompute tiers; call
    /// [`Self::recompute_all`] afterwards to propagate the change.
    pub fn set_manual_floor(&mut self, id: &ContactId, floor: Option<Tier>) {
        if let Some(c) = self.contacts.get_mut(id) {
            c.manual_floor = floor;
        }
    }

    fn active(&self, id: &ContactId) -> bool {
        matches!(self.contacts.get(id).map(|c| c.status), Some(Status::Active))
    }

    /// The tier that governs how much weight a contact's vouch carries: the larger of its
    /// cached derived tier and any user-set anchor floor. Reading this (rather than the
    /// raw cached field) means anchors confer trust immediately, before a full recompute.
    fn effective_tier(&self, id: &ContactId) -> Tier {
        match self.contacts.get(id) {
            Some(c) => c.tier.max(c.manual_floor.unwrap_or(Tier::Invited)),
            None => Tier::Invited,
        }
    }

    fn decay(&self, age_seconds: i64) -> f64 {
        let age_days = (age_seconds.max(0) as f64) / 86_400.0;
        0.5_f64.powf(age_days / self.params.half_life_days)
    }

    /// Active, non-revoked vouches about `subject` whose voucher is a known active
    /// contact (and not the subject itself).
    fn effective_vouches<'a>(&'a self, subject: &'a ContactId) -> impl Iterator<Item = &'a Vouch> {
        self.vouches.iter().filter(move |v| {
            &v.subject == subject
                && &v.voucher != subject
                && !v.revoked
                && self.active(&v.voucher)
        })
    }

    /// Count distinct vouchers backing `subject` (no clustering applied).
    pub fn distinct_vouchers(&self, subject: &ContactId) -> usize {
        let mut set: HashSet<ContactId> = HashSet::new();
        for v in self.effective_vouches(subject) {
            set.insert(v.voucher);
        }
        set.len()
    }

    /// Partition `subject`'s effective vouchers into Sybil-resistant clusters, returning a
    /// map from each voucher to a stable cluster representative.
    ///
    /// Two vouchers that vouch for each other are treated as a single source of trust: an
    /// attacker who controls a tight cluster of fake contacts must not be able to
    /// manufacture "independent" vouches just by having their puppets vouch for the
    /// target. We union vouchers connected by an active vouch (in either direction) and
    /// the connected components are the clusters. This stays strictly within the user's
    /// 1-hop horizon — we only look at vouches the user already holds (`S3`).
    ///
    /// This is a deliberately conservative *placeholder* heuristic (parameters and shape
    /// to be tuned with partners). Known limits, to be hardened later:
    /// - A star-shaped puppet set (puppets that never vouch for *each other*, only for the
    ///   target) is not collapsed by this edge rule alone — invitation-only growth and
    ///   accountable vouching are the primary defences against that, not this check.
    /// - Conversely, genuinely independent vouchers who happen to also vouch for each
    ///   other are over-collapsed into one source. Safety-biased: under-counting trust is
    ///   cheaper than over-counting it for this population.
    fn voucher_components(&self, subject: &ContactId) -> HashMap<ContactId, usize> {
        // Sort for determinism: identical inputs must always yield identical components,
        // independent of `HashMap`/`HashSet` iteration order.
        let mut vouchers: Vec<ContactId> = {
            let mut set: HashSet<ContactId> = HashSet::new();
            for v in self.effective_vouches(subject) {
                set.insert(v.voucher);
            }
            set.into_iter().collect()
        };
        vouchers.sort_unstable();

        let index: HashMap<ContactId, usize> =
            vouchers.iter().enumerate().map(|(i, id)| (*id, i)).collect();
        let mut uf = UnionFind::new(vouchers.len());
        for v in &self.vouches {
            if v.revoked {
                continue;
            }
            // Union two vouchers-of-`subject` when one vouched for the other.
            if let (Some(&a), Some(&b)) = (index.get(&v.voucher), index.get(&v.subject)) {
                uf.union(a, b);
            }
        }

        let mut out: HashMap<ContactId, usize> = HashMap::with_capacity(vouchers.len());
        for (id, &i) in &index {
            out.insert(*id, uf.find(i));
        }
        out
    }

    /// Count *independent* vouchers backing `subject`, discounting Sybil clusters
    /// (see [`Self::voucher_components`]).
    pub fn independent_voucher_count(&self, subject: &ContactId) -> usize {
        let comps = self.voucher_components(subject);
        comps.values().copied().collect::<HashSet<usize>>().len()
    }

    /// Compute the trust score in [0, 1] for `subject` as of `now` (unix seconds).
    pub fn score(&self, subject: &ContactId, now: i64) -> f64 {
        let Some(c) = self.contacts.get(subject) else { return 0.0 };
        if c.status == Status::Burned {
            return 0.0;
        }

        let base = match c.added_via {
            AddedVia::Invite => self.params.invite_base,
            AddedVia::VouchedIntro => self.params.vouched_intro_base,
        };

        // Independent clusters accumulate, but each cluster contributes only its single
        // strongest vouch — so a Sybil cluster (or one voucher vouching repeatedly) can
        // never inflate the score beyond one genuine source. This keeps the *score*
        // consistent with `independent_voucher_count`, which gates the tiers.
        let comps = self.voucher_components(subject);
        let mut per_cluster: HashMap<usize, f64> = HashMap::new();
        for v in self.effective_vouches(subject) {
            let Some(&cluster) = comps.get(&v.voucher) else { continue };
            let voucher_tier = self.effective_tier(&v.voucher);
            let w = (v.weight.clamp(1, 3) as f64) / 3.0;
            let contribution = w * tier_weight(voucher_tier) * self.decay(now - v.created_at);
            let slot = per_cluster.entry(cluster).or_insert(0.0);
            *slot = slot.max(contribution);
        }
        let vouch_score: f64 = per_cluster.values().sum();

        let burn_penalty: f64 = self
            .burns
            .iter()
            .filter(|b| &b.subject == subject && &b.origin != subject && self.active(&b.origin))
            .map(|b| self.params.burn_coefficient * tier_weight(self.effective_tier(&b.origin)))
            .sum();

        (base + vouch_score - burn_penalty).clamp(0.0, 1.0)
    }

    /// Pure tier computation for `subject` from its current score and *independent* vouch
    /// count. Reads vouchers' *cached* tiers only (no recursion → strictly 1-hop, `S3`).
    /// Does not mutate; [`Self::recompute_tier`] and [`Self::recompute_all`] commit it.
    fn compute_tier(&self, subject: &ContactId, now: i64) -> Tier {
        let Some(c) = self.contacts.get(subject) else { return Tier::Invited };
        // A burn overrides everything, including a manual anchor — safety wins.
        if c.status == Status::Burned {
            return Tier::Invited;
        }
        let s = self.score(subject, now);
        let vouchers = self.independent_voucher_count(subject);
        let p = self.params;

        let derived = if vouchers >= 3 && s >= p.t3_threshold {
            Tier::Core
        } else if vouchers >= 2 && s >= p.t2_threshold {
            Tier::Trusted
        } else if vouchers >= 1 && s >= p.t1_threshold {
            Tier::Vouched
        } else {
            Tier::Invited
        };

        derived.max(c.manual_floor.unwrap_or(Tier::Invited))
    }

    /// Recompute and cache `subject`'s tier from its current score and vouch count.
    /// Returns the new tier.
    ///
    /// This updates only `subject`. Because a contact's cached tier feeds the
    /// `voucher_trust` of anyone they vouch for, a single change can cascade; prefer
    /// [`Self::recompute_all`] after any mutation that can ripple (a burn, a revocation,
    /// or a vouch from/for an established contact).
    pub fn recompute_tier(&mut self, subject: &ContactId, now: i64) -> Tier {
        let tier = self.compute_tier(subject, now);
        if let Some(c) = self.contacts.get_mut(subject) {
            c.tier = tier;
        }
        tier
    }

    /// Recompute and cache the tier of **every** contact, with a deterministic,
    /// order-independent result.
    ///
    /// Each pass computes new tiers from the tiers committed by the *previous* pass (a
    /// two-phase update over a sorted contact list), so the outcome never depends on
    /// `HashMap` iteration order, and changes propagate along vouch chains pass by pass.
    /// Passes repeat until a fixpoint, bounded by the number of contacts so the routine
    /// always terminates even if a vouch cycle would otherwise oscillate. Returns the
    /// number of passes performed.
    pub fn recompute_all(&mut self, now: i64) -> usize {
        let mut ids: Vec<ContactId> = self.contacts.keys().copied().collect();
        ids.sort_unstable();

        let max_passes = ids.len() + 1;
        let mut passes = 0;
        for _ in 0..max_passes {
            passes += 1;
            let updates: Vec<(ContactId, Tier)> =
                ids.iter().map(|id| (*id, self.compute_tier(id, now))).collect();
            let mut changed = false;
            for (id, tier) in updates {
                if let Some(c) = self.contacts.get_mut(&id) {
                    if c.tier != tier {
                        c.tier = tier;
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        passes
    }
}

/// Minimal disjoint-set (union-find) with path compression and union by size.
struct UnionFind {
    parent: Vec<usize>,
    size: Vec<usize>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self { parent: (0..n).collect(), size: vec![1; n] }
    }

    fn find(&mut self, x: usize) -> usize {
        let mut root = x;
        while self.parent[root] != root {
            root = self.parent[root];
        }
        // Path compression.
        let mut cur = x;
        while self.parent[cur] != root {
            let next = self.parent[cur];
            self.parent[cur] = root;
            cur = next;
        }
        root
    }

    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra == rb {
            return;
        }
        let (big, small) = if self.size[ra] >= self.size[rb] { (ra, rb) } else { (rb, ra) };
        self.parent[small] = big;
        self.size[big] += self.size[small];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;
    const NOW: i64 = 1_900_000_000;

    fn id(n: u8) -> ContactId {
        let mut a = [0u8; 16];
        a[0] = n;
        a
    }

    /// Build a graph with two well-established (Core) vouchers we can rely on in tests.
    /// They are personally trusted **anchors** (the realistic way a contact reaches a high
    /// tier without being vouched), so they survive `recompute_all`.
    fn graph_with_two_core_vouchers() -> (TrustGraph, ContactId, ContactId) {
        let mut g = TrustGraph::new(TrustParams::default());
        let (a, b) = (id(1), id(2));
        g.upsert_contact(Contact::new(a, AddedVia::Invite).with_manual_floor(Tier::Core));
        g.upsert_contact(Contact::new(b, AddedVia::Invite).with_manual_floor(Tier::Core));
        (g, a, b)
    }

    #[test]
    fn invited_contact_starts_at_tier0() {
        let mut g = TrustGraph::new(TrustParams::default());
        let s = id(10);
        g.upsert_contact(Contact::new(s, AddedVia::Invite));
        assert_eq!(g.recompute_tier(&s, NOW), Tier::Invited);
        assert!(g.contact(&s).unwrap().tier.capabilities().direct_message);
        assert!(!g.contact(&s).unwrap().tier.capabilities().group_chat);
    }

    #[test]
    fn single_vouch_promotes_to_tier1() {
        let (mut g, a, _b) = graph_with_two_core_vouchers();
        let s = id(10);
        g.upsert_contact(Contact::new(s, AddedVia::VouchedIntro));
        g.add_vouch(Vouch { subject: s, voucher: a, weight: 3, created_at: NOW, revoked: false });

        assert_eq!(g.distinct_vouchers(&s), 1);
        assert_eq!(g.recompute_tier(&s, NOW), Tier::Vouched);
        assert!(g.contact(&s).unwrap().tier.capabilities().group_chat);
        assert!(!g.contact(&s).unwrap().tier.capabilities().file_sharing);
    }

    #[test]
    fn two_independent_vouches_reach_tier2() {
        let (mut g, a, b) = graph_with_two_core_vouchers();
        let s = id(10);
        g.upsert_contact(Contact::new(s, AddedVia::VouchedIntro));
        g.add_vouch(Vouch { subject: s, voucher: a, weight: 3, created_at: NOW, revoked: false });
        g.add_vouch(Vouch { subject: s, voucher: b, weight: 3, created_at: NOW, revoked: false });

        assert_eq!(g.distinct_vouchers(&s), 2);
        assert_eq!(g.recompute_tier(&s, NOW), Tier::Trusted);
        assert!(g.contact(&s).unwrap().tier.capabilities().file_sharing);
    }

    #[test]
    fn a_credible_burn_outweighs_vouches() {
        let (mut g, a, b) = graph_with_two_core_vouchers();
        let s = id(10);
        g.upsert_contact(Contact::new(s, AddedVia::VouchedIntro));
        g.add_vouch(Vouch { subject: s, voucher: a, weight: 3, created_at: NOW, revoked: false });
        g.add_vouch(Vouch { subject: s, voucher: b, weight: 3, created_at: NOW, revoked: false });
        assert_eq!(g.recompute_tier(&s, NOW), Tier::Trusted);

        // A Core contact flags the subject as compromised.
        g.add_burn(BurnSignal { subject: s, origin: a, created_at: NOW });
        let dropped = g.recompute_tier(&s, NOW);
        assert!(dropped < Tier::Trusted, "burn must lower the tier");
    }

    #[test]
    fn burned_subject_loses_all_trust() {
        let (mut g, a, _b) = graph_with_two_core_vouchers();
        let s = id(10);
        g.upsert_contact(Contact::new(s, AddedVia::VouchedIntro));
        g.add_vouch(Vouch { subject: s, voucher: a, weight: 3, created_at: NOW, revoked: false });
        g.set_status(&s, Status::Burned);
        assert_eq!(g.score(&s, NOW), 0.0);
        assert_eq!(g.recompute_tier(&s, NOW), Tier::Invited);
    }

    #[test]
    fn old_vouches_decay() {
        let (mut g, a, _b) = graph_with_two_core_vouchers();
        let s = id(10);
        g.upsert_contact(Contact::new(s, AddedVia::VouchedIntro));
        // A vouch one half-life (180 days) old should be worth ~half a fresh one.
        let old = NOW - 180 * DAY;
        g.add_vouch(Vouch { subject: s, voucher: a, weight: 3, created_at: old, revoked: false });
        let aged = g.score(&s, NOW);

        let mut g2 = TrustGraph::new(TrustParams::default());
        g2.upsert_contact(Contact::new(a, AddedVia::Invite).with_manual_floor(Tier::Core));
        g2.upsert_contact(Contact::new(s, AddedVia::VouchedIntro));
        g2.add_vouch(Vouch { subject: s, voucher: a, weight: 3, created_at: NOW, revoked: false });
        let fresh = g2.score(&s, NOW);

        assert!(aged < fresh, "older vouch must contribute less");
    }

    #[test]
    fn mutually_vouching_cluster_counts_as_one_source() {
        // Two Core contacts both vouch for the subject — but they also vouch for each
        // other, so they are a single cluster and must not unlock Tier 2.
        let (mut g, c, d) = graph_with_two_core_vouchers();
        let s = id(10);
        g.upsert_contact(Contact::new(s, AddedVia::VouchedIntro));
        g.add_vouch(Vouch { subject: s, voucher: c, weight: 3, created_at: NOW, revoked: false });
        g.add_vouch(Vouch { subject: s, voucher: d, weight: 3, created_at: NOW, revoked: false });
        // The cluster: c and d vouch for each other.
        g.add_vouch(Vouch { subject: d, voucher: c, weight: 3, created_at: NOW, revoked: false });
        g.add_vouch(Vouch { subject: c, voucher: d, weight: 3, created_at: NOW, revoked: false });

        assert_eq!(g.distinct_vouchers(&s), 2);
        assert_eq!(g.independent_voucher_count(&s), 1, "cluster must collapse to one source");
        assert_eq!(g.recompute_tier(&s, NOW), Tier::Vouched, "Sybil cluster must not reach Tier 2");
    }

    #[test]
    fn revoking_a_vouch_drops_the_tier() {
        let (mut g, a, _b) = graph_with_two_core_vouchers();
        let s = id(10);
        g.upsert_contact(Contact::new(s, AddedVia::VouchedIntro));
        g.add_vouch(Vouch { subject: s, voucher: a, weight: 3, created_at: NOW, revoked: false });
        assert_eq!(g.recompute_tier(&s, NOW), Tier::Vouched);

        assert_eq!(g.revoke_vouch(&s, &a), 1);
        assert_eq!(g.distinct_vouchers(&s), 0);
        assert_eq!(g.recompute_tier(&s, NOW), Tier::Invited);
    }

    #[test]
    fn revoke_vouches_by_a_contact_affects_all_their_vouches() {
        let (mut g, a, _b) = graph_with_two_core_vouchers();
        let (s1, s2) = (id(10), id(11));
        g.upsert_contact(Contact::new(s1, AddedVia::VouchedIntro));
        g.upsert_contact(Contact::new(s2, AddedVia::VouchedIntro));
        g.add_vouch(Vouch { subject: s1, voucher: a, weight: 3, created_at: NOW, revoked: false });
        g.add_vouch(Vouch { subject: s2, voucher: a, weight: 3, created_at: NOW, revoked: false });

        assert_eq!(g.revoke_vouches_by(&a), 2);
        assert_eq!(g.recompute_tier(&s1, NOW), Tier::Invited);
        assert_eq!(g.recompute_tier(&s2, NOW), Tier::Invited);
    }

    #[test]
    fn vouch_from_burned_voucher_is_ignored() {
        let (mut g, a, _b) = graph_with_two_core_vouchers();
        let s = id(10);
        g.upsert_contact(Contact::new(s, AddedVia::VouchedIntro));
        g.add_vouch(Vouch { subject: s, voucher: a, weight: 3, created_at: NOW, revoked: false });
        g.set_status(&a, Status::Burned);
        assert_eq!(g.distinct_vouchers(&s), 0);
        assert_eq!(g.recompute_tier(&s, NOW), Tier::Invited);
    }

    #[test]
    fn independent_vouches_accumulate_in_score() {
        // Two independent vouchers must score strictly higher than one — the whole point
        // of the web of trust is that genuinely independent vouches add up.
        let (mut g, a, b) = graph_with_two_core_vouchers();
        let s = id(10);
        g.upsert_contact(Contact::new(s, AddedVia::VouchedIntro));
        g.add_vouch(Vouch { subject: s, voucher: a, weight: 1, created_at: NOW, revoked: false });
        let one = g.score(&s, NOW);
        g.add_vouch(Vouch { subject: s, voucher: b, weight: 1, created_at: NOW, revoked: false });
        let two = g.score(&s, NOW);
        assert!(two > one, "a second independent vouch must raise the score");
    }

    #[test]
    fn sybil_cluster_does_not_inflate_score() {
        // A mutually-vouching cluster must contribute no more to the score than a single
        // one of its members would — otherwise the count check and the score check could
        // disagree and a cluster could buy trust it shouldn't.
        let (mut g, c, d) = graph_with_two_core_vouchers();
        let s = id(10);
        g.upsert_contact(Contact::new(s, AddedVia::VouchedIntro));
        g.add_vouch(Vouch { subject: s, voucher: c, weight: 3, created_at: NOW, revoked: false });
        g.add_vouch(Vouch { subject: s, voucher: d, weight: 3, created_at: NOW, revoked: false });
        g.add_vouch(Vouch { subject: d, voucher: c, weight: 3, created_at: NOW, revoked: false });
        g.add_vouch(Vouch { subject: c, voucher: d, weight: 3, created_at: NOW, revoked: false });
        let cluster_score = g.score(&s, NOW);

        // One lone Core voucher, same weight, for comparison.
        let (mut g2, e, _f) = graph_with_two_core_vouchers();
        let s2 = id(11);
        g2.upsert_contact(Contact::new(s2, AddedVia::VouchedIntro));
        g2.add_vouch(Vouch { subject: s2, voucher: e, weight: 3, created_at: NOW, revoked: false });
        let single_score = g2.score(&s2, NOW);

        assert!(
            (cluster_score - single_score).abs() < 1e-9,
            "a Sybil cluster must score the same as a single source"
        );
    }

    #[test]
    fn repeated_vouches_from_one_voucher_count_once() {
        // A single voucher vouching many times is one source, in both count and score.
        let (mut g, a, _b) = graph_with_two_core_vouchers();
        let s = id(10);
        g.upsert_contact(Contact::new(s, AddedVia::VouchedIntro));
        g.add_vouch(Vouch { subject: s, voucher: a, weight: 3, created_at: NOW, revoked: false });
        let once = g.score(&s, NOW);
        g.add_vouch(Vouch { subject: s, voucher: a, weight: 3, created_at: NOW, revoked: false });
        g.add_vouch(Vouch { subject: s, voucher: a, weight: 3, created_at: NOW, revoked: false });
        assert_eq!(g.independent_voucher_count(&s), 1);
        assert!((g.score(&s, NOW) - once).abs() < 1e-9, "duplicate vouches must not stack");
    }

    #[test]
    fn score_is_always_within_bounds() {
        // Even pathological inputs (many vouches, many burns) stay clamped to [0, 1].
        let (mut g, a, b) = graph_with_two_core_vouchers();
        let s = id(10);
        g.upsert_contact(Contact::new(s, AddedVia::VouchedIntro));
        for _ in 0..50 {
            g.add_vouch(Vouch { subject: s, voucher: a, weight: 3, created_at: NOW, revoked: false });
            g.add_vouch(Vouch { subject: s, voucher: b, weight: 3, created_at: NOW, revoked: false });
            g.add_burn(BurnSignal { subject: s, origin: a, created_at: NOW });
        }
        let sc = g.score(&s, NOW);
        assert!((0.0..=1.0).contains(&sc), "score {sc} escaped [0, 1]");
    }

    #[test]
    fn recompute_all_is_order_independent_and_idempotent() {
        // recompute_all must converge to the same cached tiers regardless of HashMap
        // ordering, and running it again must change nothing.
        let (mut g, a, b) = graph_with_two_core_vouchers();
        let (s1, s2) = (id(10), id(11));
        g.upsert_contact(Contact::new(s1, AddedVia::VouchedIntro));
        g.upsert_contact(Contact::new(s2, AddedVia::VouchedIntro));
        g.add_vouch(Vouch { subject: s1, voucher: a, weight: 3, created_at: NOW, revoked: false });
        g.add_vouch(Vouch { subject: s1, voucher: b, weight: 3, created_at: NOW, revoked: false });
        g.add_vouch(Vouch { subject: s2, voucher: a, weight: 3, created_at: NOW, revoked: false });

        g.recompute_all(NOW);
        let t1 = g.contact(&s1).unwrap().tier;
        let t2 = g.contact(&s2).unwrap().tier;
        assert_eq!(t1, Tier::Trusted);
        assert_eq!(t2, Tier::Vouched);

        let passes = g.recompute_all(NOW);
        assert_eq!(passes, 1, "a settled graph must converge in a single pass");
        assert_eq!(g.contact(&s1).unwrap().tier, t1);
        assert_eq!(g.contact(&s2).unwrap().tier, t2);
    }

    #[test]
    fn recompute_all_propagates_along_a_vouch_chain() {
        // A contact's cached tier feeds the trust it can confer. `leaf` is vouched only by
        // `m`, and `m` only by `core`: `leaf` can only clear Tier 1 once `m` has itself
        // been promoted. A single naive pass (with `m` still at Tier 0, tier_weight 0.2)
        // would leave `leaf` below threshold; the multi-pass fixpoint is what carries it.
        let mut g = TrustGraph::new(TrustParams::default());
        let core = id(1);
        g.upsert_contact(Contact::new(core, AddedVia::Invite).with_manual_floor(Tier::Core));

        let (m, leaf) = (id(2), id(3));
        g.upsert_contact(Contact::new(m, AddedVia::VouchedIntro));
        g.upsert_contact(Contact::new(leaf, AddedVia::VouchedIntro));
        g.add_vouch(Vouch { subject: m, voucher: core, weight: 3, created_at: NOW, revoked: false });
        g.add_vouch(Vouch { subject: leaf, voucher: m, weight: 3, created_at: NOW, revoked: false });

        let passes = g.recompute_all(NOW);
        assert!(g.contact(&m).unwrap().tier >= Tier::Vouched);
        assert!(
            g.contact(&leaf).unwrap().tier >= Tier::Vouched,
            "promotion must propagate from core -> m -> leaf"
        );
        assert!(passes >= 2, "chain promotion needs more than one pass");
    }

    #[test]
    fn manual_anchor_is_a_floor_that_survives_recompute_but_yields_to_a_burn() {
        let mut g = TrustGraph::new(TrustParams::default());
        let anchor = id(1);
        // A personally-trusted, in-person contact, anchored at Trusted despite no vouches.
        g.upsert_contact(Contact::new(anchor, AddedVia::Invite).with_manual_floor(Tier::Trusted));

        g.recompute_all(NOW);
        assert_eq!(g.contact(&anchor).unwrap().tier, Tier::Trusted, "anchor floor must hold");

        // Burning the anchor overrides the floor — safety wins.
        g.set_status(&anchor, Status::Burned);
        g.recompute_all(NOW);
        assert_eq!(g.contact(&anchor).unwrap().tier, Tier::Invited);
    }

    #[test]
    fn recompute_all_demotes_the_whole_neighbourhood_after_a_burn() {
        // Burning a voucher must, after a full sweep, strip the tiers it was propping up.
        let mut g = TrustGraph::new(TrustParams::default());
        let core = id(1);
        g.upsert_contact(Contact::new(core, AddedVia::Invite).with_manual_floor(Tier::Core));
        let s = id(2);
        g.upsert_contact(Contact::new(s, AddedVia::VouchedIntro));
        g.add_vouch(Vouch { subject: s, voucher: core, weight: 3, created_at: NOW, revoked: false });

        g.recompute_all(NOW);
        assert!(g.contact(&s).unwrap().tier >= Tier::Vouched);

        g.set_status(&core, Status::Burned);
        g.recompute_all(NOW);
        assert_eq!(g.contact(&s).unwrap().tier, Tier::Invited, "burned voucher must stop conferring trust");
    }
}
