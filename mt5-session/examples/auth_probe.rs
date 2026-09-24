use mt5_session::{Session, UnsupportedLoginProfile};

fn variable(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} must be set"))
}

fn probe() -> Result<(), String> {
    let address = variable("MT5_ADDRESS")?;
    let login = variable("MT5_LOGIN")?
        .parse::<u64>()
        .map_err(|_| "invalid MT5_LOGIN")?;
    let password = variable("MT5_PASSWORD")?;
    let build = variable("MT5_BUILD")?
        .parse::<u16>()
        .map_err(|_| "invalid MT5_BUILD")?;
    let otp = std::env::var("MT5_OTP").ok();
    let mut session = Session::connect(address).map_err(|e| e.to_string())?;
    let outcome = session.authenticate_with_otp(login, &password, build, otp.as_deref());
    if let Some(summary) = session.auth_summary() {
        println!("{summary:?}");
    }
    let summary = outcome.map_err(|e| e.to_string())?;
    if summary.certificate_required {
        return Err(
            "certificate continuation required; use the library with a provisioned signer".into(),
        );
    }
    session
        .resolve_login_values(&UnsupportedLoginProfile)
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn main() {
    if let Err(error) = probe() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
