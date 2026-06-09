//! Small-group end-to-end messaging (req `7.3`, milestone 1.7).
//!
//! Group chat uses the audited **Megolm** group ratchet (pure-Rust `vodozemac`) — we never
//! roll our own. Megolm is the efficient counterpart to the 1:1 Double Ratchet
//! ([`crate::messaging`]): each member has one *outbound* sending ratchet whose key is shared
//! once with the other members, who hold a matching *inbound* ratchet per sender. A message is
//! encrypted once and fanned out, instead of separately per recipient.
//!
//! ## Why the spec's "OpenMLS" became Megolm
//!
//! The spec named OpenMLS (RFC 9420). Megolm provides the same group-E2EE shape we need for
//! the MVP (sender ratchets, forward secrecy, key rotation on membership change) from the
//! crate we already depend on and that is independently audited, keeping the build pure and
//! hermetic. MLS's tree-based continuous group key agreement is a worthwhile later upgrade for
//! large/!dynamic groups; this is recorded as a deviation in `docs/technical-spec.md`.
//!
//! ## Trust gating and key rotation
//!
//! Group membership is **tier-gated**: only contacts whose tier grants `group_chat`
//! (Tier 1 / [`Tier::Vouched`] and above, per the threat model §6) may be added
//! ([`Group::add_member`]). Removing a member ([`Group::remove_member`]) **rotates** our
//! outbound ratchet, so the removed member — who still holds our old sender key — cannot read
//! anything we send afterwards (post-compromise security on removal). The new sender key is
//! then redistributed to the remaining members. A member added later is given the sender key at
//! its *current* ratchet index, so it cannot decrypt earlier history (forward secrecy on join).
//!
//! ## Shape of the API
//!
//! Each member owns a [`Group`] holding their outbound ratchet, an inbound ratchet per other
//! member, and the roster. Members exchange [`SenderKeyDistribution`]s over their 1:1 channels
//! ([`crate::messaging`]); each is installed with [`Group::accept_sender_key`]. Thereafter a
//! group message is a [`GroupCiphertext`] (sender + group id + Megolm message) produced by
//! [`Group::encrypt`] and read with [`Group::decrypt`]; on the wire it is padded
//! ([`crate::framing`]) and delivered to each member's queue ([`crate::queue`]). The
//! disappearing-message TTL rides inside the encrypted payload, exactly as for 1:1.

use std::collections::{BTreeSet, HashMap};

use vodozemac::megolm::{
    GroupSession as MegolmGroupSession, InboundGroupSession, MegolmMessage, SessionConfig, SessionKey,
};

use crate::messaging::PlainMessage;
use crate::trust::{ContactId, Tier};

const ID_LEN: usize = 16;

/// A random, local identifier for a group conversation.
pub type GroupId = [u8; ID_LEN];

/// Why a group operation failed.
#[derive(Debug, PartialEq, Eq)]
pub enum GroupError {
    /// The contact's tier is too low to be in a group (needs `group_chat`, i.e. Tier 1+).
    BelowTier,
    /// The referenced contact is not a member of this group.
    NotAMember,
    /// No inbound session is installed for the message's sender (their key was never accepted).
    UnknownSender,
    /// Authenticated decryption failed: wrong/rotated sender key, or tampering.
    Decrypt,
    /// A wire object was structurally invalid or addressed to a different group.
    Malformed,
}

/// A member's outbound Megolm sender key, distributed to the other members (over their secure
/// 1:1 channels) so they can decrypt that member's group messages.
pub struct SenderKeyDistribution {
    /// The group this key is for.
    pub group: GroupId,
    /// The member whose sending ratchet this key belongs to.
    pub sender: ContactId,
    key: SessionKey,
}

impl SenderKeyDistribution {
    /// Encode for delivery over a 1:1 channel: `group(16) || sender(16) || session_key`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let key = self.key.to_bytes();
        let mut out = Vec::with_capacity(ID_LEN + ID_LEN + key.len());
        out.extend_from_slice(&self.group);
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&key);
        out
    }

    /// Decode a distribution received over a 1:1 channel.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GroupError> {
        if bytes.len() < ID_LEN + ID_LEN {
            return Err(GroupError::Malformed);
        }
        let mut group = [0u8; ID_LEN];
        let mut sender = [0u8; ID_LEN];
        group.copy_from_slice(&bytes[..ID_LEN]);
        sender.copy_from_slice(&bytes[ID_LEN..2 * ID_LEN]);
        let key = SessionKey::from_bytes(&bytes[2 * ID_LEN..]).map_err(|_| GroupError::Malformed)?;
        Ok(Self { group, sender, key })
    }
}

/// An encrypted group message: which group, which sender, and the Megolm ciphertext. This is
/// what gets padded and fanned out to members' queues.
pub struct GroupCiphertext {
    pub group: GroupId,
    pub sender: ContactId,
    message: MegolmMessage,
}

impl GroupCiphertext {
    /// Encode for the wire: `group(16) || sender(16) || megolm-message`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let message = self.message.to_bytes();
        let mut out = Vec::with_capacity(ID_LEN + ID_LEN + message.len());
        out.extend_from_slice(&self.group);
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&message);
        out
    }

    /// Decode a group message received from the wire.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GroupError> {
        if bytes.len() < ID_LEN + ID_LEN {
            return Err(GroupError::Malformed);
        }
        let mut group = [0u8; ID_LEN];
        let mut sender = [0u8; ID_LEN];
        group.copy_from_slice(&bytes[..ID_LEN]);
        sender.copy_from_slice(&bytes[ID_LEN..2 * ID_LEN]);
        let message = MegolmMessage::from_bytes(&bytes[2 * ID_LEN..]).map_err(|_| GroupError::Malformed)?;
        Ok(Self { group, sender, message })
    }
}

/// One member's view of a group: their outbound sending ratchet, an inbound ratchet per other
/// member, and the roster. Construct with [`Group::create`].
pub struct Group {
    group_id: GroupId,
    me: ContactId,
    outbound: MegolmGroupSession,
    inbound: HashMap<ContactId, InboundGroupSession>,
    roster: BTreeSet<ContactId>,
}

impl Group {
    /// Start a group as `me`. A fresh outbound ratchet is created; share its key with each
    /// member you add via [`sender_key`](Group::sender_key).
    pub fn create(group_id: GroupId, me: ContactId) -> Self {
        let mut roster = BTreeSet::new();
        roster.insert(me);
        Self {
            group_id,
            me,
            outbound: MegolmGroupSession::new(SessionConfig::version_1()),
            inbound: HashMap::new(),
            roster,
        }
    }

    /// This group's local identifier.
    pub fn group_id(&self) -> GroupId {
        self.group_id
    }

    /// The current roster (members, including `me`).
    pub fn members(&self) -> impl Iterator<Item = &ContactId> {
        self.roster.iter()
    }

    /// Our current outbound sender key, to distribute to members. Call this after creating the
    /// group, after adding a member, and after every removal-triggered rotation. The key
    /// reflects the ratchet's *current* index, so a member who installs it cannot read messages
    /// we sent earlier (forward secrecy on join).
    pub fn sender_key(&self) -> SenderKeyDistribution {
        SenderKeyDistribution { group: self.group_id, sender: self.me, key: self.outbound.session_key() }
    }

    /// Add a member, enforcing the tier gate. `tier` is the member's tier in the local trust
    /// graph (looked up by the caller). Rejected with [`GroupError::BelowTier`] unless the tier
    /// grants `group_chat` (Tier 1+).
    pub fn add_member(&mut self, member: ContactId, tier: Tier) -> Result<(), GroupError> {
        if !tier.capabilities().group_chat {
            return Err(GroupError::BelowTier);
        }
        self.roster.insert(member);
        Ok(())
    }

    /// Remove a member and **rotate** our outbound ratchet so the removed member cannot read
    /// anything we send afterwards. Redistribute [`sender_key`](Group::sender_key) to the
    /// remaining members after calling this.
    pub fn remove_member(&mut self, member: &ContactId) -> Result<(), GroupError> {
        if !self.roster.remove(member) {
            return Err(GroupError::NotAMember);
        }
        self.inbound.remove(member);
        self.outbound = MegolmGroupSession::new(SessionConfig::version_1());
        Ok(())
    }

    /// Install another member's sender key so we can decrypt their group messages. The sender
    /// must already be on the roster and the key must be for this group.
    pub fn accept_sender_key(&mut self, skd: SenderKeyDistribution) -> Result<(), GroupError> {
        if skd.group != self.group_id {
            return Err(GroupError::Malformed);
        }
        if !self.roster.contains(&skd.sender) {
            return Err(GroupError::NotAMember);
        }
        let inbound = InboundGroupSession::new(&skd.key, SessionConfig::version_1());
        self.inbound.insert(skd.sender, inbound);
        Ok(())
    }

    /// Encrypt a message to the group, advancing our outbound ratchet.
    pub fn encrypt(&mut self, msg: &PlainMessage) -> GroupCiphertext {
        let message = self.outbound.encrypt(msg.encode());
        GroupCiphertext { group: self.group_id, sender: self.me, message }
    }

    /// Decrypt a group message using the inbound ratchet for its sender.
    pub fn decrypt(&mut self, ciphertext: &GroupCiphertext) -> Result<PlainMessage, GroupError> {
        if ciphertext.group != self.group_id {
            return Err(GroupError::Malformed);
        }
        let inbound = self.inbound.get_mut(&ciphertext.sender).ok_or(GroupError::UnknownSender)?;
        let decrypted = inbound.decrypt(&ciphertext.message).map_err(|_| GroupError::Decrypt)?;
        PlainMessage::decode(&decrypted.plaintext).map_err(|_| GroupError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(n: u8) -> ContactId {
        let mut id = [0u8; ID_LEN];
        id[0] = n;
        id
    }

    const GID: GroupId = [42u8; ID_LEN];

    /// Build a fully-connected group over `members` (all at a group-capable tier): every member
    /// has every other on the roster and has installed everyone's (index-0) sender key.
    fn connect(members: &[ContactId]) -> HashMap<ContactId, Group> {
        let mut groups: HashMap<ContactId, Group> =
            members.iter().map(|&m| (m, Group::create(GID, m))).collect();

        // Everyone admits everyone else.
        for &m in members {
            for &other in members {
                if other != m {
                    groups.get_mut(&m).unwrap().add_member(other, Tier::Trusted).unwrap();
                }
            }
        }
        // Everyone distributes their index-0 sender key; everyone installs it.
        let distributions: Vec<_> =
            members.iter().map(|m| groups.get(m).unwrap().sender_key().to_bytes()).collect();
        for &m in members {
            for skd in &distributions {
                let skd = SenderKeyDistribution::from_bytes(skd).unwrap();
                if skd.sender != m {
                    groups.get_mut(&m).unwrap().accept_sender_key(skd).unwrap();
                }
            }
        }
        groups
    }

    #[test]
    fn a_message_fans_out_to_every_member() {
        let (a, b, c) = (cid(1), cid(2), cid(3));
        let mut groups = connect(&[a, b, c]);

        let ct = groups.get_mut(&a).unwrap().encrypt(&PlainMessage::new(b"meet at the usual place".to_vec()));
        assert_eq!(groups.get_mut(&b).unwrap().decrypt(&ct).unwrap().body, b"meet at the usual place");
        assert_eq!(groups.get_mut(&c).unwrap().decrypt(&ct).unwrap().body, b"meet at the usual place");
    }

    #[test]
    fn every_member_can_originate() {
        let (a, b, c) = (cid(1), cid(2), cid(3));
        let mut groups = connect(&[a, b, c]);

        let from_b = groups.get_mut(&b).unwrap().encrypt(&PlainMessage::new(b"from bob".to_vec()));
        assert_eq!(groups.get_mut(&a).unwrap().decrypt(&from_b).unwrap().body, b"from bob");
        assert_eq!(groups.get_mut(&c).unwrap().decrypt(&from_b).unwrap().body, b"from bob");
    }

    #[test]
    fn a_below_tier_contact_cannot_be_added() {
        let mut group = Group::create(GID, cid(1));
        assert_eq!(group.add_member(cid(2), Tier::Invited).unwrap_err(), GroupError::BelowTier);
        // A Tier-1 (Vouched) contact is allowed.
        assert!(group.add_member(cid(3), Tier::Vouched).is_ok());
    }

    #[test]
    fn a_message_from_an_uninstalled_sender_is_unknown() {
        let (a, b) = (cid(1), cid(2));
        let mut alice = Group::create(GID, a);
        let mut bob = Group::create(GID, b);
        alice.add_member(b, Tier::Trusted).unwrap();
        bob.add_member(a, Tier::Trusted).unwrap();
        // Bob never installs Alice's sender key.
        let ct = alice.encrypt(&PlainMessage::new(b"hello".to_vec()));
        assert_eq!(bob.decrypt(&ct).unwrap_err(), GroupError::UnknownSender);
    }

    #[test]
    fn removing_a_member_rotates_the_key_so_they_lose_access() {
        let (a, b, c) = (cid(1), cid(2), cid(3));
        let mut groups = connect(&[a, b, c]);

        // Baseline: C can read A's messages.
        let before = groups.get_mut(&a).unwrap().encrypt(&PlainMessage::new(b"still in".to_vec()));
        assert_eq!(groups.get_mut(&c).unwrap().decrypt(&before).unwrap().body, b"still in");

        // A removes C, which rotates A's outbound ratchet, then redistributes the new sender
        // key to the *remaining* member (B) before sending anything more.
        groups.get_mut(&a).unwrap().remove_member(&c).unwrap();
        let new_key = groups.get(&a).unwrap().sender_key().to_bytes();
        groups
            .get_mut(&b)
            .unwrap()
            .accept_sender_key(SenderKeyDistribution::from_bytes(&new_key).unwrap())
            .unwrap();
        let after = groups.get_mut(&a).unwrap().encrypt(&PlainMessage::new(b"C is gone".to_vec()));

        // C's stale inbound session for A cannot decrypt post-rotation traffic.
        assert_eq!(groups.get_mut(&c).unwrap().decrypt(&after).unwrap_err(), GroupError::Decrypt);

        // B, holding A's rotated sender key, can still read.
        assert_eq!(groups.get_mut(&b).unwrap().decrypt(&after).unwrap().body, b"C is gone");
    }

    #[test]
    fn a_member_added_later_cannot_read_history() {
        let (a, b, late) = (cid(1), cid(2), cid(9));
        let mut groups = connect(&[a, b]);

        // A sends a message before `late` joins.
        let history = groups.get_mut(&a).unwrap().encrypt(&PlainMessage::new(b"old secret".to_vec()));

        // `late` joins; A admits them and shares the sender key at its *current* index.
        let mut late_group = Group::create(GID, late);
        late_group.add_member(a, Tier::Trusted).unwrap();
        groups.get_mut(&a).unwrap().add_member(late, Tier::Trusted).unwrap();
        let key_now = groups.get(&a).unwrap().sender_key().to_bytes();
        late_group.accept_sender_key(SenderKeyDistribution::from_bytes(&key_now).unwrap()).unwrap();

        // The newcomer cannot read the pre-join message...
        assert_eq!(late_group.decrypt(&history).unwrap_err(), GroupError::Decrypt);
        // ...but can read what comes after.
        let fresh = groups.get_mut(&a).unwrap().encrypt(&PlainMessage::new(b"new info".to_vec()));
        assert_eq!(late_group.decrypt(&fresh).unwrap().body, b"new info");
    }

    #[test]
    fn the_disappearing_ttl_is_preserved() {
        let (a, b) = (cid(1), cid(2));
        let mut groups = connect(&[a, b]);
        let msg = PlainMessage { body: b"burn after reading".to_vec(), ttl_secs: Some(60) };
        let ct = groups.get_mut(&a).unwrap().encrypt(&msg);
        assert_eq!(groups.get_mut(&b).unwrap().decrypt(&ct).unwrap(), msg);
    }

    #[test]
    fn ciphertext_and_distribution_round_trip_through_bytes() {
        let (a, b) = (cid(1), cid(2));
        let mut groups = connect(&[a, b]);

        let ct = groups.get_mut(&a).unwrap().encrypt(&PlainMessage::new(b"wire".to_vec()));
        let restored = GroupCiphertext::from_bytes(&ct.to_bytes()).unwrap();
        assert_eq!(groups.get_mut(&b).unwrap().decrypt(&restored).unwrap().body, b"wire");
    }

    #[test]
    fn a_tampered_group_message_is_rejected() {
        let (a, b) = (cid(1), cid(2));
        let mut groups = connect(&[a, b]);
        let ct = groups.get_mut(&a).unwrap().encrypt(&PlainMessage::new(b"integrity".to_vec()));

        let mut bytes = ct.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = GroupCiphertext::from_bytes(&bytes).unwrap();
        assert_eq!(groups.get_mut(&b).unwrap().decrypt(&tampered).unwrap_err(), GroupError::Decrypt);
    }

    #[test]
    fn a_key_for_a_non_member_is_rejected() {
        let mut alice = Group::create(GID, cid(1));
        // Bob is not on Alice's roster; his key is refused.
        let bob = Group::create(GID, cid(2));
        let skd = SenderKeyDistribution::from_bytes(&bob.sender_key().to_bytes()).unwrap();
        assert_eq!(alice.accept_sender_key(skd).unwrap_err(), GroupError::NotAMember);
    }
}
