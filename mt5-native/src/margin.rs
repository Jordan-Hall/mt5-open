//! Retail margin in the account currency. Conversion rates are supplied by the
//! caller: positions retain their broker rate; pending orders use current quotes.
use crate::{
    error::{ProtocolError, Result},
    records::Symbol,
};

/// Group margin flag verified by toggling SYMBOL_MARGIN_HEDGED_USE_LEG in
/// otherwise identical custom symbols in terminal build 6182.
pub const HEDGED_LARGER_LEG: u32 = 4;

#[derive(Debug, Clone, Copy)]
pub struct Exposure {
    pub kind: usize,
    pub volume_units: u64,
    pub price: f64,
    pub conversion: f64,
}

fn amount(
    s: &Symbol,
    lots: f64,
    price: f64,
    leverage: i32,
    fixed: Option<f64>,
    contract: f64,
) -> Option<f64> {
    if !lots.is_finite()
        || lots < 0.0
        || !price.is_finite()
        || price <= 0.0
        || !contract.is_finite()
        || contract < 0.0
        || fixed.is_some_and(|f| !f.is_finite() || f < 0.0)
    {
        return None;
    }
    let base = match s.calculation_mode {
        0 if leverage > 0 => lots * fixed.unwrap_or(contract) / leverage as f64,
        5 => lots * fixed.unwrap_or(contract),
        2 | 32 | 36 => lots * fixed.unwrap_or(contract * price),
        4 if leverage > 0 => lots * fixed.unwrap_or(contract * price) / leverage as f64,
        3 if s.tick_size > 0.0 => {
            lots * fixed.unwrap_or(contract * price * s.tick_value / s.tick_size)
        }
        1 | 33 => lots * fixed.unwrap_or(0.0),
        _ => return None,
    };
    (base.is_finite() && base >= 0.0).then_some(base)
}

/// Unconverted margin for an order or an existing position. Maintenance rates
/// are separate from opening rates, including when the fixed amount is unchanged.
pub fn order_margin(
    s: &Symbol,
    lots: f64,
    price: f64,
    kind: usize,
    leverage: i32,
    maintenance: bool,
) -> Option<f64> {
    if !valid_terms(s) {
        return None;
    }
    let rate = *(if maintenance {
        &s.maintenance_margin_rates
    } else {
        &s.margin_rates
    })
    .get(kind)?;
    if !rate.is_finite() || rate < 0.0 {
        return None;
    }
    let fixed = if maintenance && s.maintenance_margin > 0.0 {
        Some(s.maintenance_margin)
    } else if s.initial_margin > 0.0 {
        Some(s.initial_margin)
    } else {
        None
    };
    let result = amount(s, lots, price, leverage, fixed, s.contract_size)? * rate;
    (result.is_finite() && result >= 0.0).then_some(result)
}

#[derive(Clone, Copy, Default)]
struct Leg {
    units: u64,
    price_sum: f64,
    conversion_sum: f64,
}

impl Leg {
    fn add(&mut self, e: &Exposure) -> Result<()> {
        if !e.price.is_finite()
            || e.price <= 0.0
            || !e.conversion.is_finite()
            || e.conversion <= 0.0
        {
            return Err(ProtocolError::new(
                "margin requires a positive price and currency conversion",
            ));
        }
        self.units = self
            .units
            .checked_add(e.volume_units)
            .ok_or_else(|| ProtocolError::new("margin volume overflow"))?;
        self.price_sum += e.price * e.volume_units as f64;
        self.conversion_sum += e.conversion * e.volume_units as f64;
        Ok(())
    }
    fn price(self) -> f64 {
        self.price_sum / self.units as f64
    }
    fn conversion(self) -> f64 {
        self.conversion_sum / self.units as f64
    }
    fn margin(self, s: &Symbol, kind: usize, leverage: i32, maintenance: bool) -> Result<f64> {
        if self.units == 0 {
            return Ok(0.0);
        }
        order_margin(
            s,
            self.units as f64 / 1e8,
            self.price(),
            kind,
            leverage,
            maintenance,
        )
        .map(|v| v * self.conversion())
        .ok_or_else(unsupported)
    }
}

fn valid_terms(s: &Symbol) -> bool {
    s.margin_flags & !HEDGED_LARGER_LEG == 0
        && [s.initial_margin, s.maintenance_margin, s.hedged_margin]
            .iter()
            .all(|value| value.is_finite() && *value >= 0.0)
}

fn unsupported() -> ProtocolError {
    ProtocolError::new("unsupported native retail margin terms")
}

/// Both documented retail hedging methods, including nonzero pending margins.
/// Floating tiers, exchange portfolios and spread discounts require other terms.
/// Return an unrounded value; account currency rounding follows aggregation.
pub fn hedging_margin(
    s: &Symbol,
    leverage: i32,
    positions: &[Exposure],
    orders: &[Exposure],
) -> Result<f64> {
    if !valid_terms(s) {
        return Err(unsupported());
    }
    let mut legs = [Leg::default(); 2];
    for e in positions {
        legs.get_mut(e.kind)
            .ok_or_else(|| ProtocolError::new("invalid position margin side"))?
            .add(e)?;
    }
    let mut pending = [Leg::default(); 8];
    for e in orders {
        if !(2..=7).contains(&e.kind) {
            return Err(ProtocolError::new("invalid pending margin type"));
        }
        pending[e.kind].add(e)?;
    }
    let mut pending_by_side = [0.0; 2];
    for kind in 2..8 {
        // Zero rates do not require an otherwise unused instrument formula.
        if s.margin_rates[kind] != 0.0 {
            pending_by_side[kind % 2] += pending[kind].margin(s, kind, leverage, false)?;
        }
    }
    let total = if s.margin_flags & HEDGED_LARGER_LEG != 0 {
        (legs[0].margin(s, 0, leverage, true)? + pending_by_side[0])
            .max(legs[1].margin(s, 1, leverage, true)? + pending_by_side[1])
    } else {
        let larger = usize::from(legs[1].units > legs[0].units);
        let covered = legs[0].units.min(legs[1].units);
        let uncovered = legs[larger].units - covered;
        let mut value = pending_by_side.iter().sum::<f64>();
        if uncovered > 0 {
            value += order_margin(
                s,
                uncovered as f64 / 1e8,
                legs[larger].price(),
                larger,
                leverage,
                true,
            )
            .ok_or_else(unsupported)?
                * legs[larger].conversion();
        }
        if covered > 0 && s.hedged_margin != 0.0 {
            let units = legs[0]
                .units
                .checked_add(legs[1].units)
                .ok_or_else(|| ProtocolError::new("margin volume overflow"))?
                as f64;
            let price = (legs[0].price_sum + legs[1].price_sum) / units;
            let conversion = (legs[0].conversion_sum + legs[1].conversion_sum) / units;
            let rate = (s.maintenance_margin_rates[0] + s.maintenance_margin_rates[1]) / 2.0;
            if !rate.is_finite() || rate < 0.0 {
                return Err(unsupported());
            }
            let fixed = (s.initial_margin > 0.0).then_some(s.hedged_margin);
            value += amount(
                s,
                covered as f64 / 1e8,
                price,
                leverage,
                fixed,
                s.hedged_margin,
            )
            .ok_or_else(unsupported)?
                * rate
                * conversion;
        }
        value
    };
    if total.is_finite() && total >= 0.0 {
        Ok(total)
    } else {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn symbol() -> Symbol {
        let mut s = Symbol::parse(&[0; 1952], &[0; 1228]).unwrap();
        s.contract_size = 100_000.0;
        s.margin_rates = [1.0; 8];
        s.maintenance_margin_rates = [1.0; 8];
        s
    }
    fn e(kind: usize, lots: f64, price: f64, conversion: f64) -> Exposure {
        Exposure {
            kind,
            volume_units: (lots * 1e8).round() as u64,
            price,
            conversion,
        }
    }
    #[test]
    fn documented_weighted_hedging_example() {
        let mut s = symbol();
        s.hedged_margin = 100_000.0;
        s.maintenance_margin_rates[0] = 2.0;
        s.maintenance_margin_rates[1] = 4.0;
        let v = hedging_margin(
            &s,
            500,
            &[e(1, 3.0, 1.11943, 1.11943), e(0, 2.0, 1.11953, 1.11953)],
            &[],
        )
        .unwrap();
        // The published inputs sum to 2238.908; round only the account total.
        assert!((v - 2238.908).abs() < 1e-9);
        assert_eq!((v * 100.0).round() / 100.0, 2238.91);
    }
    #[test]
    fn fixed_hedge_and_uncovered_maintenance_are_separate() {
        let mut s = symbol();
        s.calculation_mode = 1;
        s.initial_margin = 1000.0;
        s.maintenance_margin = 500.0;
        s.hedged_margin = 500.0;
        assert_eq!(
            hedging_margin(&s, 100, &[e(0, 1.0, 10.0, 1.0), e(1, 2.0, 10.0, 1.0)], &[]).unwrap(),
            1000.0
        );
    }
    #[test]
    fn larger_leg_includes_pending_orders_and_opening_rates() {
        let mut s = symbol();
        s.margin_flags = HEDGED_LARGER_LEG;
        s.initial_margin = 1000.0;
        s.maintenance_margin = 500.0;
        let positions = [e(0, 2.0, 1.0, 1.0), e(1, 3.0, 1.0, 1.0)];
        assert_eq!(
            hedging_margin(&s, 100, &positions, &[e(2, 2.0, 1.0, 1.0)]).unwrap(),
            30.0
        );
        s.margin_flags = 0;
        s.hedged_margin = 0.0;
        assert_eq!(
            hedging_margin(&s, 100, &positions, &[e(2, 2.0, 1.0, 1.0)]).unwrap(),
            25.0
        );
    }
    #[test]
    fn fully_covered_zero_hedge_is_free_but_pending_orders_are_not() {
        let s = symbol();
        let positions = [e(0, 1.0, 1.0, 1.0), e(1, 1.0, 1.0, 1.0)];
        assert_eq!(hedging_margin(&s, 100, &positions, &[]).unwrap(), 0.0);
        assert_eq!(
            hedging_margin(
                &s,
                100,
                &positions,
                &[e(2, 0.1, 1.0, 1.0), e(3, 0.1, 1.0, 1.0)]
            )
            .unwrap(),
            200.0
        );
    }
    #[test]
    fn unsupported_terms_and_invalid_rates_do_not_produce_zero_margin() {
        let mut s = symbol();
        s.margin_flags = 1;
        assert!(hedging_margin(&s, 100, &[e(0, 1.0, 1.0, 1.0)], &[]).is_err());
        s.margin_flags = 0;
        s.calculation_mode = 34;
        assert!(hedging_margin(&s, 100, &[e(0, 1.0, 1.0, 1.0)], &[]).is_err());
        s.calculation_mode = 0;
        assert!(hedging_margin(&s, 100, &[e(0, 1.0, 1.0, 0.0)], &[]).is_err());
    }
    #[test]
    fn malformed_fixed_terms_cannot_fall_back_to_contract_margin() {
        for value in [f64::NAN, f64::INFINITY, -1.0] {
            let mut s = symbol();
            s.initial_margin = value;
            assert_eq!(order_margin(&s, 1.0, 1.2, 0, 100, false), None);
            assert!(hedging_margin(&s, 100, &[e(0, 1.0, 1.2, 1.0)], &[]).is_err());
            s.initial_margin = 0.0;
            s.maintenance_margin = value;
            assert_eq!(order_margin(&s, 1.0, 1.2, 0, 100, true), None);
            s.maintenance_margin = 0.0;
            s.hedged_margin = value;
            assert!(
                hedging_margin(&s, 100, &[e(0, 1.0, 1.2, 1.0), e(1, 1.0, 1.2, 1.0)], &[]).is_err()
            );
        }
    }
}
