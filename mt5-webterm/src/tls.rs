//! Cached public-PKI trust with hostname, chain and handshake-signature checks.

use rustls::{ClientConfig, RootCertStore};
use std::sync::{Arc, OnceLock};

static CONFIG: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();

pub fn client_config() -> Result<Arc<ClientConfig>, String> {
    CONFIG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Arc::new(config))
    }).clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_certificates_are_not_accepted() {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots), Arc::new(rustls::crypto::ring::default_provider())
        ).build().unwrap();
        assert!(verifier.verify_server_cert(
            &CertificateDer::from(vec![0x30, 0]), &[], &ServerName::try_from("broker.example").unwrap(),
            &[], UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000))
        ).is_err());
    }

    #[test]
    fn verified_configuration_is_reused() {
        let a = client_config().unwrap();
        let b = client_config().unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }
}
