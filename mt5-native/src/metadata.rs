//! Application identity sent in synchronization tag 127.

/// Identify this client without inventing a terminal signature or host identity.
pub fn environment_metadata(client_build: u32) -> String {
    format!(
        "file=mt5-open\tversion={client_build}\tos_ver={}\t",
        std::env::consts::OS
    )
}
