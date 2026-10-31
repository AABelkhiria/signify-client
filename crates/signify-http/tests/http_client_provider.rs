//! The production transport ignores the process-wide rustls provider. A separate binary, because
//! an installed default cannot be removed again.

#![cfg(feature = "http-client")]

use std::error::Error;

use rustls::crypto::{CryptoProvider, ring};
use signify_http::transport::HttpTransport;

#[test]
fn the_transport_ignores_the_process_default_rustls_provider() -> Result<(), Box<dyn Error>> {
    // A default the transport could not use: it offers no cipher suites.
    let unusable = CryptoProvider {
        cipher_suites: Vec::new(),
        ..ring::default_provider()
    };
    unusable
        .install_default()
        .map_err(|_| "a default provider was already installed")?;

    HttpTransport::new()?;
    Ok(())
}
