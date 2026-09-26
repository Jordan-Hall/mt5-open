use super::Client;
use mt5_native::{
    error::{ProtocolError, Result},
    margin::{Exposure, hedging_margin, order_margin},
};
use std::collections::BTreeMap;

impl Client {
    /// Retail account margin from synchronized terms and broker position rates.
    /// Unsupported portfolio or dynamic terms return an error, never a zero estimate.
    pub fn margin(&self) -> Result<f64> {
        let terms = self
            .state
            .terms
            .as_ref()
            .ok_or_else(|| ProtocolError::new("missing account margin terms"))?;
        if !(0..=8).contains(&terms.currency_digits) {
            return Err(ProtocolError::new("invalid account currency precision"));
        }
        let mut symbols: BTreeMap<&str, (Vec<Exposure>, Vec<Exposure>)> = BTreeMap::new();
        for p in &self.state.positions {
            if p.volume == 0 {
                continue;
            }
            symbols.entry(&p.symbol).or_default().0.push(Exposure {
                kind: p
                    .kind
                    .try_into()
                    .map_err(|_| ProtocolError::new("invalid position margin side"))?,
                volume_units: p.volume,
                price: p.price_open,
                conversion: p.margin_rate,
            });
        }
        for o in &self.state.orders {
            if o.volume == 0 {
                continue;
            }
            let s = self.symbol(&o.symbol)?;
            let kind: usize = o
                .kind
                .try_into()
                .map_err(|_| ProtocolError::new("invalid pending margin type"))?;
            if !(2..=7).contains(&kind) {
                return Err(ProtocolError::new("invalid pending margin type"));
            }
            if s.margin_rates[kind] == 0.0 {
                continue;
            }
            let conversion = self
                .conversion_rate(&s.margin_currency, &terms.currency, kind % 2 == 0)
                .ok_or_else(|| {
                    ProtocolError::new("pending margin currency conversion is unavailable")
                })?;
            symbols.entry(&o.symbol).or_default().1.push(Exposure {
                kind,
                volume_units: o.volume,
                price: o.price,
                conversion,
            });
        }
        let mut total = 0.0;
        for (name, (positions, orders)) in symbols {
            if terms.margin_mode != 1 {
                return Err(ProtocolError::new("unsupported account margin model"));
            }
            let s = self.symbol(name)?;
            if terms.accounting_method == 2 {
                total += hedging_margin(s, self.state.account.leverage, &positions, &orders)?;
            } else if positions.len() <= 1 && orders.is_empty() {
                for p in positions {
                    if !p.conversion.is_finite() || p.conversion <= 0.0 {
                        return Err(ProtocolError::new("position margin conversion is missing"));
                    }
                    total += order_margin(
                        s,
                        p.volume_units as f64 / 1e8,
                        p.price,
                        p.kind,
                        self.state.account.leverage,
                        true,
                    )
                    .ok_or_else(|| ProtocolError::new("unsupported native retail margin terms"))?
                        * p.conversion;
                }
            } else {
                return Err(ProtocolError::new(
                    "native netting order margin requires broker validation",
                ));
            }
        }
        if !total.is_finite() || total < 0.0 {
            return Err(ProtocolError::new("invalid calculated account margin"));
        }
        let scale = 10f64.powi(terms.currency_digits);
        Ok((total * scale).round() / scale)
    }
}
