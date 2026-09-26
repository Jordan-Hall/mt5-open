//! Web-terminal wire format and trade record.

use rand::Rng;

pub const CMD_AUTH: u16 = 0;
pub const CMD_ACCOUNT: u16 = 3;
pub const CMD_POSITIONS: u16 = 4;
pub const CMD_DEALS: u16 = 5;
pub const CMD_SUBSCRIBE: u16 = 7;
pub const CMD_QUOTES: u16 = 8;
pub const CMD_RATES: u16 = 11;
pub const CMD_TRADE: u16 = 12;
/// Pushed after a subscription: last bid/ask and session statistics per symbol.
pub const CMD_TICK_STATS: u16 = 17;
/// Full symbol specifications for a u32 count and that many symbol ids.
pub const CMD_SYMBOL_INFO: u16 = 18;
pub const CMD_TRADE_EVENT: u16 = 19;
pub const CMD_LOGIN: u16 = 28;
pub const CMD_SYMBOLS: u16 = 34;
pub const CMD_HEARTBEAT: u16 = 51;

pub const TRADE_MARKET: u32 = 3;
pub const TRADE_PENDING: u32 = 5;
pub const TRADE_MODIFY: u32 = 6;
pub const TRADE_MODIFY_ORDER: u32 = 7;
pub const TRADE_CANCEL: u32 = 8;
pub const TYPE_BUY: u32 = 0;
pub const TYPE_SELL: u32 = 1;
pub const FILL_FOK: u32 = 0;
pub const FILL_RETURN: u32 = 2;
pub const TIME_GTC: u32 = 0;
pub const LOT_MULTIPLIER: f64 = 100_000_000.0;
pub const OP_SIZE: usize = 248;
pub const LOGIN_SIZE: usize = 912;
pub const QUOTE_SIZE: usize = 50;
pub const ORDER_REC_SIZE: usize = 356;

pub fn pack_wire(encrypted: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + encrypted.len());
    out.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(encrypted);
    out
}

pub fn build_command(cmd_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut cmd = vec![0u8; 4 + payload.len()];
    cmd[0] = rng.r#gen();
    cmd[1] = rng.r#gen();
    cmd[2..4].copy_from_slice(&cmd_id.to_le_bytes());
    cmd[4..].copy_from_slice(payload);
    cmd
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub tag: u16,
    pub cmd_id: u16,
    pub res_code: u8,
    pub body: Vec<u8>,
}

pub fn parse_response(data: &[u8]) -> Option<Frame> {
    if data.len() < 5 {
        return None;
    }
    Some(Frame {
        tag: u16::from_le_bytes([data[0], data[1]]),
        cmd_id: u16::from_le_bytes([data[2], data[3]]),
        res_code: data[4],
        body: data[5..].to_vec(),
    })
}

pub fn utf16_le(s: &str, width: usize) -> Vec<u8> {
    let mut out = vec![0u8; width];
    for (i, unit) in s.encode_utf16().enumerate() {
        let o = i * 2;
        if o + 1 >= width {
            break;
        }
        out[o] = (unit & 0xff) as u8;
        out[o + 1] = (unit >> 8) as u8;
    }
    out
}

pub fn from_utf16_le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

pub fn pack_login(login: u64, password: &str, server: &str) -> Vec<u8> {
    let mut pl = vec![0u8; LOGIN_SIZE];
    let pw = utf16_le(password, (password.encode_utf16().count() * 2).min(LOGIN_SIZE.saturating_sub(4)));
    let n = pw.len().min(LOGIN_SIZE - 4);
    pl[4..4 + n].copy_from_slice(&pw[..n]);
    let ip = utf16_le(server, 256);
    let chars = server.encode_utf16().count() as u32;
    pl[476..480].copy_from_slice(&chars.to_le_bytes());
    let ipn = ip.len().min(LOGIN_SIZE - 480);
    pl[480..480 + ipn].copy_from_slice(&ip[..ipn]);
    pl[736..744].copy_from_slice(&login.to_le_bytes());
    pl
}

pub fn pack_op(
    symbol: &str,
    action_id: u32,
    trade_action: u32,
    volume_lots: f64,
    digits: u32,
    trade_type: u32,
    price: f64,
    sl: f64,
    tp: f64,
    trade_order: u64,
    type_filling: u32,
    comment: &str,
    trade_position: u64,
    price_trigger: f64,
    price_deviation: u32,
) -> Vec<u8> {
    let mut op = vec![0u8; OP_SIZE];
    op[0..4].copy_from_slice(&action_id.to_le_bytes());
    op[4..8].copy_from_slice(&trade_action.to_le_bytes());
    let sym = utf16_le(symbol, 64);
    op[8..72].copy_from_slice(&sym);
    let volume = (volume_lots * LOT_MULTIPLIER) as u64;
    op[72..80].copy_from_slice(&volume.to_le_bytes());
    op[80..84].copy_from_slice(&digits.to_le_bytes());
    op[84..92].copy_from_slice(&trade_order.to_le_bytes());
    op[92..96].copy_from_slice(&trade_type.to_le_bytes());
    op[96..100].copy_from_slice(&type_filling.to_le_bytes());
    op[100..104].copy_from_slice(&TIME_GTC.to_le_bytes());
    op[104..108].copy_from_slice(&2u32.to_le_bytes()); // type_flags
    op[112..120].copy_from_slice(&price.to_le_bytes());
    op[120..128].copy_from_slice(&price_trigger.to_le_bytes());
    op[128..136].copy_from_slice(&sl.to_le_bytes());
    op[136..144].copy_from_slice(&tp.to_le_bytes());
    op[144..148].copy_from_slice(&price_deviation.to_le_bytes());
    let cmt = utf16_le(comment, 64);
    op[164..228].copy_from_slice(&cmt);
    op[228..236].copy_from_slice(&trade_position.to_le_bytes());
    op
}

pub fn tf_wire(tf: &str) -> u16 {
    match tf {
        "M1" => 1,
        "M5" => 5,
        "M15" => 15,
        "M30" => 30,
        "H1" => 16385,
        "H4" => 16388,
        "D1" => 16408,
        _ => 5,
    }
}

pub fn pack_rates_req(symbol: &str, tf: &str, from_sec: i32, to_sec: i32) -> Vec<u8> {
    let mut pl = vec![0u8; 74];
    let sym = utf16_le(symbol, 64);
    pl[0..64].copy_from_slice(&sym);
    pl[64..66].copy_from_slice(&tf_wire(tf).to_le_bytes());
    pl[66..70].copy_from_slice(&from_sec.to_le_bytes());
    pl[70..74].copy_from_slice(&to_sec.to_le_bytes());
    pl
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_layout() {
        let pl = pack_login(12345678, "secret", "ExampleBroker-Demo");
        assert_eq!(pl.len(), 912);
        assert_eq!(u64::from_le_bytes(pl[736..744].try_into().unwrap()), 12345678);
        assert_eq!(u32::from_le_bytes(pl[476..480].try_into().unwrap()), "ExampleBroker-Demo".encode_utf16().count() as u32);
    }

    #[test]
    fn op_size() {
        let op = pack_op("XAUUSD", 1, TRADE_MARKET, 0.01, 2, TYPE_BUY, 2000.0, 1990.0, 2010.0, 0, FILL_FOK, "gd", 0, 0.0, 30);
        assert_eq!(op.len(), 248);
    }
}
