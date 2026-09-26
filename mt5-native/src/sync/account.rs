//! Locate the account by consuming the complete modern synchronization grammar.
//! Unknown fields retain their documented widths; unknown tags are errors.

use crate::account::{ACCOUNT_REC_SIZE, AccountState, parse_account_rec};
use crate::error::{ProtocolError, Result};
use crate::records::{AccountTerms, Deal, Order, Record, Symbol};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPoint {
    pub name: String,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SynchronizedState {
    pub account: AccountState,
    pub terms: Option<AccountTerms>,
    pub symbols: Vec<Symbol>,
    pub orders: Vec<Order>,
    pub positions: Vec<Deal>,
    pub server_timezone_minutes: Option<i32>,
    pub access_points: Vec<AccessPoint>,
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        if size > self.remaining.len() {
            return Err(ProtocolError::new("truncated synchronization record"));
        }
        let (value, rest) = self.remaining.split_at(size);
        self.remaining = rest;
        Ok(value)
    }

    fn word(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn count(&mut self) -> Result<usize> {
        let count = self.word()?;
        if count < 0 || count as usize > self.remaining.len() {
            return Err(ProtocolError::new("invalid synchronization count"));
        }
        Ok(count as usize)
    }

    fn array(&mut self, stride: usize) -> Result<()> {
        let count = self.count()?;
        let size = count
            .checked_mul(stride)
            .ok_or_else(|| ProtocolError::new("synchronization array overflow"))?;
        self.take(size)?;
        Ok(())
    }

    fn changed(&mut self) -> Result<bool> {
        match self.word()? {
            0 => Ok(true),
            1 => Ok(false),
            status => Err(ProtocolError::new(format!(
                "unsupported synchronization collection status {status}"
            ))),
        }
    }

    fn symbol_foundation(&mut self) -> Result<(AccountTerms, Vec<Symbol>)> {
        let terms = AccountTerms::parse(self.take(4228)?)?;
        let mut symbols = Vec::new();
        self.array(1228)?;
        for _ in 0..self.count()? {
            self.take(908)?;
            self.array(160)?;
        }
        self.take(656)?;
        for _ in 0..self.count()? {
            self.take(932)?;
            self.array(160)?;
        }
        if self.changed()? {
            for _ in 0..self.count()? {
                let info = self.take(1952)?;
                let group = self.take(1228)?;
                symbols.push(Symbol::parse(info, group)?);
                for _ in 0..7 {
                    self.array(40)?;
                    self.array(40)?;
                }
                self.take(80)?;
            }
            self.array(4)?;
        }
        if self.changed()? {
            self.array(392)?;
        }
        Ok((terms, symbols))
    }

    fn routing(&mut self) -> Result<(i32, Vec<AccessPoint>)> {
        let bytes = self.take(532)?;
        let timezone = i32::from_le_bytes(bytes[396..400].try_into().unwrap());
        let mut points = Vec::new();
        for _ in 0..self.count()? {
            let name = Record::new(self.take(268)?, 268)?.text(0, 64);
            let mut addresses = Vec::new();
            for _ in 0..self.count()? {
                let address = Record::new(self.take(148)?, 148)?.text(0, 128);
                if !address.is_empty() && !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
            points.push(AccessPoint { name, addresses });
        }
        Ok((timezone, points))
    }

    fn auxiliary(&mut self) -> Result<()> {
        if self.changed()? {
            for _ in 0..self.count()? {
                self.take(100)?;
                self.array(128)?;
                self.array(128)?;
            }
            self.array(4)?;
        }
        Ok(())
    }

    fn collection103(&mut self) -> Result<()> {
        if self.changed()? {
            for _ in 0..self.count()? {
                self.take(1240)?;
                self.array(1)?;
                for size in [256, 256, 292, 292] {
                    self.array(size)?;
                }
            }
            self.array(8)?;
            self.take(16)?;
        }
        Ok(())
    }

    fn collection120(&mut self) -> Result<()> {
        for _ in 0..self.count()? {
            self.take(776)?;
            let mut size = self.count()?;
            if size == 0 {
                size = self.count()?;
            }
            self.take(size)?;
            for stride in [528, 208, 112] {
                self.array(stride)?;
            }
        }
        Ok(())
    }

    fn blobs(&mut self) -> Result<()> {
        for _ in 0..self.count()? {
            self.take(20)?;
            let size = self.count()?;
            self.take(104)?;
            self.take(size)?;
        }
        Ok(())
    }
}

/// Read the account only after every section is structurally complete.
/// The caller can retain the original stream for other account/symbol fields.
pub fn parse_sync_account(stream: &[u8], record_build: i16) -> Result<AccountState> {
    Ok(parse_synchronized_state(stream, record_build)?.account)
}

pub fn parse_synchronized_state(stream: &[u8], record_build: i16) -> Result<SynchronizedState> {
    if record_build < 4072 {
        return Err(ProtocolError::new(
            "account synchronization requires record build 4072 or newer",
        ));
    }
    let mut reader = Reader { remaining: stream };
    let status = reader.word()?;
    if status != 0 {
        return Err(ProtocolError::new(format!(
            "account synchronization rejected with status {status}"
        )));
    }
    let mut account = None;
    let mut terms = None;
    let mut symbols = Vec::new();
    let mut orders = Vec::new();
    let mut positions = Vec::new();
    let mut server_timezone_minutes = None;
    let mut access_points = Vec::new();
    while !reader.remaining.is_empty() {
        let mut tag = reader.take(1)?[0];
        if tag == 0 {
            while tag != 23 {
                tag = reader.take(1)?[0];
            }
        }
        match tag {
            7 => {
                if terms.is_some() {
                    return Err(ProtocolError::new("duplicate symbol foundation"));
                }
                let (base, batch) = reader.symbol_foundation()?;
                terms = Some(base);
                symbols = batch;
            }
            17 => reader.array(90)?,
            23 => {
                let (timezone, points) = reader.routing()?;
                server_timezone_minutes = Some(timezone);
                access_points = points;
            }
            24 => reader.array(136)?,
            31 | 36 => {
                reader.word()?;
                for _ in 0..reader.count()? {
                    if tag == 31 {
                        orders.push(Order::parse(reader.take(636)?)?);
                    } else {
                        positions.push(Deal::parse(reader.take(672)?)?);
                    }
                }
            }
            37 => {
                if account.is_some() {
                    return Err(ProtocolError::new("duplicate account in synchronization"));
                }
                account = Some(parse_account_rec(reader.take(ACCOUNT_REC_SIZE)?)?);
            }
            40 => reader.auxiliary()?,
            103 => reader.collection103()?,
            105 => reader.array(128)?,
            120 => reader.collection120()?,
            121 | 128 => reader.blobs()?,
            132 => {
                reader.take(3084)?;
                reader.array(1288)?;
            }
            139 => {
                reader.take(16)?;
            }
            _ => {
                return Err(ProtocolError::new(format!(
                    "unsupported synchronization tag {tag}"
                )));
            }
        }
    }
    let account =
        account.ok_or_else(|| ProtocolError::new("synchronization contains no account record"))?;
    Ok(SynchronizedState {
        account,
        terms,
        symbols,
        orders,
        positions,
        server_timezone_minutes,
        access_points,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_stream() -> Vec<u8> {
        let mut stream = vec![0; 4];
        stream.push(37);
        let mut record = vec![0; ACCOUNT_REC_SIZE];
        record[..8].copy_from_slice(&12345u64.to_le_bytes());
        record[1836..1844].copy_from_slice(&812.5f64.to_le_bytes());
        stream.extend(record);
        stream
    }

    #[test]
    fn reads_account_and_validates_sections_after_it() {
        let mut stream = account_stream();
        stream.push(139);
        stream.extend([0; 16]);
        let account = parse_sync_account(&stream, 5830).unwrap();
        assert_eq!(account.login, 12345);
        assert_eq!(account.balance, 812.5);
        stream.pop();
        assert!(parse_sync_account(&stream, 5830).is_err());
    }

    #[test]
    fn synchronization_retains_advertised_access_points() {
        let mut bytes = account_stream();
        bytes.push(23);
        let mut server = [0; 532];
        server[396..400].copy_from_slice(&180i32.to_le_bytes());
        bytes.extend(server);
        bytes.extend(1i32.to_le_bytes());
        let mut info = [0; 268];
        info[..4].copy_from_slice(&[b'A', 0, b'S', 0]);
        bytes.extend(info);
        bytes.extend(2i32.to_le_bytes());
        for name in ["broker.example:701", "192.0.2.1:443"] {
            let mut address = [0; 148];
            let text: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            address[..text.len()].copy_from_slice(&text);
            bytes.extend(address);
        }
        let state = parse_synchronized_state(&bytes, 5830).unwrap();
        assert_eq!(state.server_timezone_minutes, Some(180));
        assert_eq!(
            state.access_points,
            vec![AccessPoint {
                name: "AS".into(),
                addresses: vec!["broker.example:701".into(), "192.0.2.1:443".into()]
            }]
        );
        bytes.pop();
        assert!(parse_synchronized_state(&bytes, 5830).is_err());
    }

    #[test]
    fn rejects_unknown_tags_and_invalid_counts() {
        let mut stream = account_stream();
        stream.push(255);
        assert!(parse_sync_account(&stream, 5830).is_err());
        for count in [-1i32, i32::MAX] {
            let mut stream = account_stream();
            stream.push(105);
            stream.extend(count.to_le_bytes());
            assert!(parse_sync_account(&stream, 5830).is_err());
        }
        assert!(parse_sync_account(&account_stream(), 4000).is_err());
    }
}
