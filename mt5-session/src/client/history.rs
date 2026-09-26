//! Serialized native history requests and bounded pagination.
use super::Client;
use mt5_native::{
    bars::{Bar, decode_bar_history},
    error::{ProtocolError, Result},
    records::{Deal, Order},
    requests::{make_cached_tick_history_request, make_trade_history_request},
    subscription::bar_month_request,
    tick_history::{HistoricalTick, TickContainer, decode_tick_history, materialize_ticks},
    trade_history::{TradeHistory, decode_trade_history},
};
use std::collections::BTreeMap;
impl Client {
    /// Times are broker-clock seconds, matching the protocol. The application
    /// boundary owns conversion to UTC and timeframe aggregation.
    pub fn deals(&mut self, from: i64, to: i64) -> Result<Vec<Deal>> {
        if from >= to {
            return Ok(Vec::new());
        }
        let m = self.request(101, &make_trade_history_request(33, from, to))?;
        let TradeHistory::Deals(mut deals) = decode_trade_history(&m.payload)? else {
            return Err(ProtocolError::new("expected deal history"));
        };
        deals.retain(|d| d.time >= from && d.time < to);
        deals.sort_by_key(|d| (d.time, d.ticket));
        Ok(deals)
    }

    pub fn orders(&mut self, from: i64, to: i64) -> Result<Vec<Order>> {
        if from >= to {
            return Ok(Vec::new());
        }
        let m = self.request(101, &make_trade_history_request(32, from, to))?;
        let TradeHistory::Orders(mut orders) = decode_trade_history(&m.payload)? else {
            return Err(ProtocolError::new("expected order history"));
        };
        orders.retain(|o| o.time_done >= from && o.time_done < to);
        orders.sort_by_key(|o| (o.time_done, o.ticket));
        Ok(orders)
    }

    /// Broker-clock milliseconds, inclusive start and exclusive end. Requests
    /// are serialized per client; ticks with identical timestamps are retained.
    pub fn ticks(&mut self, symbol: &str, from: i64, to: i64) -> Result<Vec<HistoricalTick>> {
        self.symbol(symbol)?;
        if from >= to {
            return Ok(Vec::new());
        }
        date(from.div_euclid(1000))?;
        date((to - 1).div_euclid(1000))?;
        let first_day = from.div_euclid(86_400_000);
        let last_day = (to - 1).div_euclid(86_400_000);
        if last_day - first_day >= 31 {
            return Err(ProtocolError::new("tick range exceeds 31 days"));
        }
        let mut output = Vec::new();
        for day in first_day..=last_day {
            let (year, month, date) = date(day * 86400)?;
            let mut cached: Vec<TickContainer> = Vec::new();
            let mut completed = false;
            for _ in 0..64 {
                let descriptors: Vec<_> = cached.iter().map(|c| c.cache.clone()).collect();
                let request =
                    make_cached_tick_history_request(symbol, year, month, date, 0, &descriptors)?;
                let m = self.request(105, &request)?;
                let response = decode_tick_history(&m.payload)?;
                if response.symbol != symbol {
                    return Err(ProtocolError::new("tick history symbol mismatch"));
                }
                let before: Vec<_> = cached.iter().map(|c| c.cache.clone()).collect();
                for container in response.containers {
                    if let Some(existing) = cached
                        .iter_mut()
                        .find(|c| c.cache.date == container.cache.date)
                    {
                        *existing = container;
                    } else {
                        cached.push(container);
                    }
                }
                if cached.iter().map(|c| c.ticks.len()).sum::<usize>() > 1_000_000 {
                    return Err(ProtocolError::new("tick cache exceeds one million rows"));
                }
                if response.more {
                    if before == cached.iter().map(|c| c.cache.clone()).collect::<Vec<_>>() {
                        return Err(ProtocolError::new("tick continuation made no progress"));
                    }
                    continue;
                }
                cached.sort_by_key(|c| c.cache.date);
                let rows = materialize_ticks(
                    cached
                        .iter()
                        .chain(&response.trailing)
                        .flat_map(|c| &c.ticks),
                )?;
                output.extend(rows.into_iter().filter(|r| {
                    r.time_ms >= from && r.time_ms < to && r.time_ms.div_euclid(86_400_000) == day
                }));
                if output.len() > 1_000_000 {
                    return Err(ProtocolError::new("tick range exceeds one million rows"));
                }
                completed = true;
                break;
            }
            if !completed {
                return Err(ProtocolError::new("tick continuation limit exceeded"));
            }
        }
        output.sort_by_key(|t| t.time_ms);
        Ok(output)
    }

    pub fn bars(&mut self, symbol: &str, from: i64, to: i64) -> Result<Vec<Bar>> {
        self.symbol(symbol)?;
        if from >= to {
            return Ok(Vec::new());
        }
        let mut bars = BTreeMap::new();
        let mut before = to - 1;
        for _ in 0..256 {
            let (year, month, day) = date(before)?;
            let body = bar_month_request(symbol, year, month, day)?;
            let m = self.request(102, &body)?;
            let groups = decode_bar_history(&m.payload)?;
            let mut oldest = before;
            let mut found = false;
            for group in groups {
                if group.symbol != symbol {
                    return Err(ProtocolError::new("bar response symbol mismatch"));
                }
                for bar in group.bars {
                    found = true;
                    oldest = oldest.min(bar.time);
                    if bar.time >= from && bar.time < to {
                        bars.insert(bar.time, bar);
                    }
                }
            }
            if !found || oldest <= from {
                return Ok(bars.into_values().collect());
            }
            if oldest >= before {
                return Err(ProtocolError::new("bar pagination made no progress"));
            }
            before = oldest - 1;
        }
        Err(ProtocolError::new("bar range exceeds pagination limit"))
    }
}

fn date(seconds: i64) -> Result<(i32, i32, i32)> {
    if !(0..4_039_372_800).contains(&seconds) {
        return Err(ProtocolError::new("history time outside date-token range"));
    }
    let z = seconds / 86400 + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    y += i64::from(m <= 2);
    Ok((y as i32, m as i32, d as i32))
}
