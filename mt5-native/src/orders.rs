//! Order/command layer — the BrokerAdapter-facing surface.
//!
//! Mirrors the host application's `BrokerCommand` field for
//! field so the existing runtime maps 1:1 onto this native transport. The WIRE
//! SERIALIZATION of each command into an encrypted control-frame body is not
//! implemented; it is the single `TODO(schema)` below. Everything else — the typed surface, the adapter
//! trait, and the result/uncertainty model the host application requires — is defined here.

/// Mirrors the host application's BrokerCommand.action values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Buy,
    Sell,
    Modify,
    Cancel,
    Close,
    PartialClose,
    Breakeven,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrokerCommand {
    pub action: Action,
    pub symbol: String,
    pub volume: f64,
    pub price: f64,
    pub stop_loss: f64,
    pub take_profit: f64,
    pub comment: String,
    pub command_id: String, // durable, idempotent, correlated (host application contract)
    pub is_limit: bool,
    pub ticket: Option<u64>, // for modify/cancel/close of an existing order/position
}

/// the host application requires an explicit uncertainty state — ambiguous broker effects
/// must never become blind retries.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Ok { ticket: u64 },
    Rejected { reason: String },
    /// Effect ambiguous — must be reconciled against authoritative broker state,
    /// never blindly retried.
    Uncertain { detail: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct BridgeResult {
    pub success: bool,
    pub outcome: Outcome,
    pub command_id: String,
}

/// The native broker transport that the host application's runtime will drive, behind the
/// same boundary as the existing file/MT5 adapter.
pub trait BrokerTransport {
    fn execute(&mut self, cmd: &BrokerCommand) -> BridgeResult;
    /// Authoritative snapshot for reconciliation (positions/orders/deals).
    fn snapshot(&mut self) -> Snapshot;
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Snapshot {
    pub positions: Vec<Position>,
    pub orders: Vec<PendingOrder>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Position {
    pub ticket: u64,
    pub symbol: String,
    pub volume: f64,
    pub price_open: f64,
    pub sl: f64,
    pub tp: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PendingOrder {
    pub ticket: u64,
    pub symbol: String,
    pub volume: f64,
    pub price: f64,
    pub is_buy: bool,
}

/// Serialize a command into the canonical 800-byte trade record. Enum values are
/// the documented registries (OrderType/TradeType/FillPolicy); volume uses the
/// observed 1e8 fixed-point scaling; opaque spans and transport-supplied fields
/// (login, symbol routing, signature) stay zero here — signing and routing are a
/// transport-layer concern, and nothing is transmitted.
pub fn serialize_command(cmd: &BrokerCommand) -> crate::error::Result<Vec<u8>> {
    use crate::trade::{build_trade_record, MarketTradeFields};

    // Documented enum values.
    let (order_type, trade_type): (i32, i32) = match cmd.action {
        Action::Buy if cmd.is_limit => (2, 5),   // BuyLimit / SetOrder (pending)
        Action::Buy => (0, 3),                    // Buy / MarketExecution
        Action::Sell if cmd.is_limit => (3, 5),   // SellLimit / SetOrder (pending)
        Action::Sell => (1, 3),                   // Sell / MarketExecution
        Action::Modify | Action::Breakeven => (0, 7), // ModifyOrder
        Action::Cancel => (0, 8),                 // CancelOrder
        Action::Close | Action::PartialClose => (0, 10), // ClosePosition
    };

    build_trade_record(&MarketTradeFields {
        trade_type,
        order_type,
        fill_policy: 3, // FillPolicy::Any
        symbol: cmd.symbol.clone(),
        volume_units: (cmd.volume * 100_000_000.0).round() as u64,
        price: cmd.price,
        stop_loss: cmd.stop_loss,
        take_profit: cmd.take_profit,
        comment: cmd.comment.clone(),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_surface_mirrors_broker_command() {
        let c = BrokerCommand {
            action: Action::Buy,
            symbol: "BTCUSD".into(),
            volume: 0.01,
            price: 0.0,
            stop_loss: 76000.0,
            take_profit: 79000.0,
            comment: "gd".into(),
            command_id: "abc123".into(),
            is_limit: false,
            ticket: None,
        };
        assert_eq!(c.action, Action::Buy);
        assert_eq!(c.command_id, "abc123");
        // Serializes to the canonical 800-byte trade record and round-trips.
        let bytes = serialize_command(&c).unwrap();
        assert_eq!(bytes.len(), 800);
        let parsed = crate::trade::parse_trade_record(&bytes).unwrap();
        assert!(matches!(parsed.get("order_type"), Some(crate::trade::Value::I32(0))));
        assert!(matches!(parsed.get("trade_type"), Some(crate::trade::Value::I32(3))));
        assert!(matches!(parsed.get("volume_units"), Some(crate::trade::Value::U64(1_000_000))));
    }

    #[test]
    fn uncertain_outcome_is_representable() {
        let r = BridgeResult {
            success: false,
            outcome: Outcome::Uncertain { detail: "send ack lost".into() },
            command_id: "x".into(),
        };
        match r.outcome {
            Outcome::Uncertain { .. } => {}
            _ => panic!("expected uncertain"),
        }
    }
}
