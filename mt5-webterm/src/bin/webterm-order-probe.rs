//! Order-path proof for the web terminal, with no market risk.
//!
//! Places a BUY LIMIT far below the market (so it cannot fill), confirms the
//! broker accepted it (retcode 0 / 10009 = TRADE_DONE), then cancels it by
//! ticket and confirms the cancel. If both round-trips return done, the
//! terminal-free order path works end to end — send, accept, cancel — without
//! ever holding a position. Read-only account fields are printed for context.
//!
//! Credentials from the environment; a demo account only.

use mt5_webterm::protocol::{pack_op, FILL_FOK, FILL_RETURN, TRADE_CANCEL, TRADE_PENDING};
use mt5_webterm::Client;

const BUY_LIMIT: u32 = 2; // OrderKind::BuyLimit, matching the transport
const DIGITS: u32 = 2; // XAUUSD

#[tokio::main]
async fn main() {
    let login: u64 = std::env::var("MT5_ACCOUNT").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let password = std::env::var("MT5_PASSWORD").unwrap_or_default();
    let server = std::env::var("MT5_SERVER").unwrap_or_default();
    if login == 0 || password.is_empty() || server.is_empty() {
        eprintln!("set MT5_ACCOUNT MT5_PASSWORD MT5_SERVER");
        std::process::exit(2);
    }
    let c = match Client::connect(login, &password, &server).await {
        Ok(c) => c,
        Err(e) => { eprintln!("connect FAILED: {e}"); std::process::exit(1); }
    };
    let acct = c.account().await.expect("account");
    println!("connected login={} balance={:.2} {}", acct.login, acct.balance, acct.currency);

    // Cleanup mode: cancel one known ticket and exit. Used to clear a stray the
    // trade-event parse could not hand back a ticket for.
    if let Ok(t) = std::env::var("CANCEL_TICKET") {
        let ticket: u64 = t.parse().unwrap_or(0);
        let orders = c.orders().await.unwrap_or_default();
        let o = orders.iter().find(|o| o.ticket as u64 == ticket);
        let (sym, kind, price, vol) = match o {
            Some(o) => (o.symbol.clone(), o.kind, o.price, o.volume),
            None => { println!("ticket {ticket} not in book (already gone)"); return; }
        };
        let digits = c.symbol(&sym).await.map(|x| x.digits).unwrap_or(2);
        let op = pack_op(&sym, rand::random(), TRADE_CANCEL, vol, digits, kind, price, 0.0, 0.0, ticket, FILL_FOK, "", 0, 0.0, 30);
        let (ret, _, _, _) = c.send_op(&op).await.expect("cancel");
        let after = c.orders().await.unwrap_or_default();
        let gone = after.iter().all(|o| o.ticket as u64 != ticket);
        println!("CANCEL {ticket} -> retcode={ret} gone={gone}");
        return;
    }

    let _ = c.subscribe(&["XAUUSD".to_string()]).await;
    let q = c.wait_quote("XAUUSD").await.expect("quote");
    println!("XAUUSD {}/{}", q.bid, q.ask);

    // 100 dollars below the bid: nowhere near fillable, and well clear of any
    // stop/freeze distance, so acceptance is a clean yes.
    let price = (q.bid - 100.0).max(1.0);
    let price = (price * 100.0).round() / 100.0;
    let op = pack_op(
        "XAUUSD", rand::random(), TRADE_PENDING, 0.01, DIGITS, BUY_LIMIT,
        price, 0.0, 0.0, 0, FILL_RETURN, "order-path-probe", 0, 0.0, 30,
    );
    let (ret, _deal, order, fill) = c.send_op(&op).await.expect("send buy-limit");
    let placed_ok = ret == 0 || ret == 10009;
    println!("PLACE buy-limit @ {price} -> retcode={ret} order={order} price={fill} ok={placed_ok}");
    if !placed_ok {
        eprintln!("order path FAILED at placement (retcode {ret})");
        std::process::exit(1);
    }

    // Find it in the book to confirm it really rests there.
    let orders = c.orders().await.unwrap_or_default();
    let mine = orders.iter().find(|o| o.ticket == order);
    println!("book: {} pending; ours {}", orders.len(), if mine.is_some() { "present" } else { "NOT FOUND" });

    // Cancel it by ticket and confirm.
    let kind = mine.map(|o| o.kind).unwrap_or(BUY_LIMIT);
    let cancel = pack_op(
        "XAUUSD", rand::random(), TRADE_CANCEL, 0.01, DIGITS, kind,
        price, 0.0, 0.0, order as u64, FILL_FOK, "", 0, 0.0, 30,
    );
    let (cret, _, _, _) = c.send_op(&cancel).await.expect("cancel");
    let cancel_ok = cret == 0 || cret == 10009;
    println!("CANCEL order={order} -> retcode={cret} ok={cancel_ok}");

    let after = c.orders().await.unwrap_or_default();
    let gone = after.iter().all(|o| o.ticket != order);
    println!("after cancel: {} pending; ours {}", after.len(), if gone { "gone" } else { "STILL THERE" });

    if placed_ok && cancel_ok && gone {
        println!("ORDER PATH OK: web terminal placed and cancelled with no position held");
    } else {
        eprintln!("ORDER PATH INCOMPLETE: place_ok={placed_ok} cancel_ok={cancel_ok} gone={gone}");
        std::process::exit(1);
    }
}
