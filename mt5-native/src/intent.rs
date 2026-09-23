//! Order-intent lifecycle: what we meant to do, what we know we did.
//!
//! Trading over a network has one failure that matters more than the rest: a
//! command leaves, and the answer never comes back. The position may be open,
//! or the order may have been rejected, and from the client's side those look
//! identical — silence. The wrong reaction to silence is to send it again.
//!
//! So an intent is written down *before* it is transmitted, and it never moves
//! straight from "sent" to "done". It moves to a state that says the outcome is
//! not known, and the only way out of that state is to read the broker's own
//! record and match the intent to it. Nothing here retries on a timeout,
//! because a retry is a second trade whenever the first one actually landed.
//!
//! This is transport-independent on purpose: the same lifecycle guards the
//! official-API bridge that trades today. It is the part of a native client
//! that has to be right regardless of how the bytes eventually travel, so it is
//! built and tested with no wire at all.

use crate::orders::BrokerCommand;

/// Where an intent is in its life. The order is one-way except that any of the
/// terminal states can be reached from [`Stage::Unknown`] once the broker's
/// record is read.
#[derive(Debug, Clone, PartialEq)]
pub enum Stage {
    /// Written down, nothing sent. A crash here loses nothing: no order exists.
    Prepared,
    /// Bytes handed to the transport. Whether the broker received them is not
    /// yet known — this is the state a timeout lands in, not a retry.
    Transmitted,
    /// The broker answered, and the answer was yes: a ticket exists.
    Acknowledged { ticket: u64 },
    /// The broker answered, and the answer was no.
    Rejected { reason: String },
    /// The broker answered in part: some volume filled, some did not. Held
    /// separately because it is neither done nor failed.
    PartiallyFilled { ticket: u64, filled: f64, remaining: f64 },
    /// Resolved: the order is done (filled, or a pending cancelled).
    Settled { ticket: u64 },
    /// The outcome is not known and cannot be assumed. Reached from a timeout
    /// or a dropped connection after [`Stage::Transmitted`]. The ONLY exits are
    /// through [`Intent::reconcile`] against the broker's authoritative state.
    Unknown { detail: String },
}

impl Stage {
    /// True once the intent needs nothing more from us.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Stage::Rejected { .. } | Stage::Settled { .. })
    }

    /// True while the intent's real effect is undetermined. An intent in this
    /// state must never be resent — it must be reconciled.
    pub fn is_undetermined(&self) -> bool {
        matches!(self, Stage::Transmitted | Stage::Unknown { .. })
    }
}

/// One order, from the decision to place it to the knowledge of what happened.
#[derive(Debug, Clone, PartialEq)]
pub struct Intent {
    pub command: BrokerCommand,
    pub stage: Stage,
    /// How many times the bytes have been put on the wire. This is a fact to
    /// record, never a licence to send again — see [`Intent::may_transmit`].
    pub transmissions: u32,
}

/// Why a caller may not put an intent on the wire right now. Returning this,
/// rather than sending, is the whole point of the type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refuse {
    /// Already transmitted and not yet resolved: sending again risks a second
    /// live order for one decision. Reconcile first.
    AlreadyInFlight,
    /// Outcome unknown: the broker's record must decide what happened before
    /// anything else is sent for this intent.
    MustReconcileFirst,
    /// The intent is finished; there is nothing left to send.
    AlreadyResolved,
}

impl Intent {
    /// Write the intent down. This is the durable record that must exist before
    /// a single byte is transmitted, so that a crash mid-send is recoverable.
    pub fn prepare(command: BrokerCommand) -> Self {
        Intent { command, stage: Stage::Prepared, transmissions: 0 }
    }

    /// Whether it is safe to transmit now. Safe only from [`Stage::Prepared`]:
    /// once something is in flight or undetermined, the answer is a reason, not
    /// a yes.
    pub fn may_transmit(&self) -> Result<(), Refuse> {
        match &self.stage {
            Stage::Prepared => Ok(()),
            Stage::Transmitted => Err(Refuse::AlreadyInFlight),
            Stage::Unknown { .. } => Err(Refuse::MustReconcileFirst),
            _ if self.stage.is_terminal() => Err(Refuse::AlreadyResolved),
            _ => Err(Refuse::MustReconcileFirst),
        }
    }

    /// Record that the bytes have gone out. Call this the instant before (or
    /// after) the write, never conditionally on a reply — the reply may not
    /// come, and this state is how we remember that we are exposed.
    pub fn mark_transmitted(&mut self) {
        self.transmissions += 1;
        self.stage = Stage::Transmitted;
    }

    /// The broker acknowledged with a ticket.
    pub fn mark_acknowledged(&mut self, ticket: u64) {
        self.stage = Stage::Acknowledged { ticket };
    }

    /// The broker rejected it.
    pub fn mark_rejected(&mut self, reason: impl Into<String>) {
        self.stage = Stage::Rejected { reason: reason.into() };
    }

    /// The reply never arrived, or the connection dropped after transmitting.
    /// This is the correct reaction to a timeout: not a resend, a move into the
    /// state that forces reconciliation.
    pub fn mark_unknown(&mut self, detail: impl Into<String>) {
        // Only a transmitted intent can become unknown; a prepared one that was
        // never sent is simply still prepared.
        if matches!(self.stage, Stage::Transmitted) {
            self.stage = Stage::Unknown { detail: detail.into() };
        }
    }

    /// Resolve an undetermined intent against the broker's own record.
    ///
    /// `found` is what authoritative state says about this command — matched by
    /// the durable `command_id` the intent carries, which is how one decision is
    /// tied to one broker order even across a reconnect. This is the only way an
    /// [`Stage::Unknown`] intent leaves that state, and it never invents an
    /// outcome the record does not show.
    pub fn reconcile(&mut self, found: Reconciled) {
        match found {
            Reconciled::Filled { ticket } => self.stage = Stage::Settled { ticket },
            Reconciled::Partial { ticket, filled, remaining } => {
                self.stage = Stage::PartiallyFilled { ticket, filled, remaining }
            }
            Reconciled::Open { ticket } => self.stage = Stage::Acknowledged { ticket },
            Reconciled::Cancelled { ticket } => self.stage = Stage::Settled { ticket },
            // The broker has no record of it: the transmission did not take
            // effect, so — and only now — the intent is safe to send again.
            Reconciled::Absent => self.stage = Stage::Prepared,
        }
    }
}

/// What the broker's authoritative record shows for one intent, as found by its
/// durable command id during reconciliation.
#[derive(Debug, Clone, PartialEq)]
pub enum Reconciled {
    /// A position/order exists and is fully filled.
    Filled { ticket: u64 },
    /// Some filled, some outstanding.
    Partial { ticket: u64, filled: f64, remaining: f64 },
    /// A pending order exists, not yet filled.
    Open { ticket: u64 },
    /// The order existed and was cancelled.
    Cancelled { ticket: u64 },
    /// No trace of it: the command never landed.
    Absent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orders::Action;

    fn cmd() -> BrokerCommand {
        BrokerCommand {
            action: Action::Buy,
            symbol: "BTCUSD".into(),
            volume: 0.01,
            price: 0.0,
            stop_loss: 0.0,
            take_profit: 0.0,
            comment: "gd".into(),
            command_id: "cmd-1".into(),
            is_limit: false,
            ticket: None,
        }
    }

    #[test]
    fn an_intent_is_durable_before_it_is_sent() {
        let i = Intent::prepare(cmd());
        assert_eq!(i.stage, Stage::Prepared);
        assert_eq!(i.transmissions, 0);
        assert!(i.may_transmit().is_ok());
    }

    #[test]
    fn a_transmitted_intent_will_not_be_sent_again() {
        let mut i = Intent::prepare(cmd());
        i.mark_transmitted();
        assert_eq!(i.transmissions, 1);
        assert_eq!(i.may_transmit(), Err(Refuse::AlreadyInFlight));
    }

    #[test]
    fn a_timeout_forces_reconciliation_not_a_resend() {
        let mut i = Intent::prepare(cmd());
        i.mark_transmitted();
        i.mark_unknown("no ack in 5s");
        assert!(i.stage.is_undetermined());
        // The one thing that must not happen after a timeout: another send.
        assert_eq!(i.may_transmit(), Err(Refuse::MustReconcileFirst));
    }

    #[test]
    fn reconciling_a_landed_order_settles_it_never_resends() {
        let mut i = Intent::prepare(cmd());
        i.mark_transmitted();
        i.mark_unknown("connection dropped");
        i.reconcile(Reconciled::Filled { ticket: 5001 });
        assert_eq!(i.stage, Stage::Settled { ticket: 5001 });
        assert_eq!(i.may_transmit(), Err(Refuse::AlreadyResolved));
    }

    #[test]
    fn only_a_command_the_broker_never_saw_becomes_sendable_again() {
        let mut i = Intent::prepare(cmd());
        i.mark_transmitted();
        i.mark_unknown("connection dropped");
        i.reconcile(Reconciled::Absent);
        // Absent means it never landed, so — and only so — a resend is safe.
        assert_eq!(i.stage, Stage::Prepared);
        assert!(i.may_transmit().is_ok());
        // And the transmission count is preserved as history.
        assert_eq!(i.transmissions, 1);
    }

    #[test]
    fn a_partial_fill_is_neither_done_nor_failed() {
        let mut i = Intent::prepare(cmd());
        i.mark_transmitted();
        i.reconcile(Reconciled::Partial { ticket: 42, filled: 0.006, remaining: 0.004 });
        match i.stage {
            Stage::PartiallyFilled { ticket, filled, remaining } => {
                assert_eq!(ticket, 42);
                assert!((filled - 0.006).abs() < 1e-9);
                assert!((remaining - 0.004).abs() < 1e-9);
            }
            other => panic!("expected partial, got {other:?}"),
        }
        assert!(!i.stage.is_terminal());
    }

    #[test]
    fn a_prepared_intent_that_was_never_sent_cannot_become_unknown() {
        let mut i = Intent::prepare(cmd());
        i.mark_unknown("spurious");
        assert_eq!(i.stage, Stage::Prepared, "nothing was sent, so nothing is unknown");
    }
}
