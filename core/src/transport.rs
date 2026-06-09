//! Transport — metadata-resistant, relay-assisted delivery (req `7.4`). **STUB**.
//!
//! Modelled on SimpleX's SMP: messages travel through **anonymous unidirectional queues**
//! on **untrusted relays**, run over Tor with pluggable transports. Relays see only
//! opaque, fixed-size (padded) blobs in random queues and cannot link sender to recipient
//! or identify users. There are no user identifiers and no identity-linked push tokens
//! (req `S12`).
//!
//! This module is the **lowest-level byte pipe** to a relay endpoint — the part a concrete
//! Tor/socket client implements. The authenticated simplex-queue *protocol* (queue creation,
//! recipient/sender capability separation, signed commands) lives in [`crate::queue`], which
//! is fully implemented and tested against a reference relay; a networked relay client speaks
//! that protocol over this pipe and lands in a later milestone.

/// An opaque, fixed-size (padded) blob — all a relay ever sees.
///
/// The length-hiding padding and AEAD sealing that make a blob opaque and uniform are
/// implemented in [`crate::framing`] (pure and audited); a concrete [`Transport`] only moves
/// these blobs and must never inspect or resize them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Blob(pub Vec<u8>);

/// A one-directional anonymous queue address. Random per-contact; carries no identity.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct QueueAddr(pub Vec<u8>);

#[derive(Debug, PartialEq, Eq)]
pub enum TransportError {
    NotImplemented,
}

/// Abstract transport over untrusted relays. Implementations must pad to a fixed block
/// size and must not attach any identifier beyond the opaque queue address. **STUB**.
pub trait Transport {
    /// Enqueue a blob to a send-queue. The relay cannot read or attribute it.
    fn send(&mut self, queue: &QueueAddr, blob: &Blob) -> Result<(), TransportError>;

    /// Drain any blobs waiting on one of our receive-queues.
    fn receive(&mut self, queue: &QueueAddr) -> Result<Vec<Blob>, TransportError>;
}
