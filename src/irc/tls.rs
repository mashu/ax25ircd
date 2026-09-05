//! TLS for the IP listener.
//!
//! The radio hop is in the clear by law. The hop from an internet IRC client
//! to this process is not: OPER, IDENTIFY and a connection password are
//! transmitter control, and they do not belong on a plaintext socket.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// Install the ring crypto provider. Safe to call more than once.
pub fn ensure_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Load a PEM certificate chain and private key and build a TLS acceptor.
pub fn acceptor(cert_path: &str, key_path: &str) -> anyhow::Result<TlsAcceptor> {
    Ok(TlsAcceptor::from(Arc::new(server_config(
        cert_path, key_path,
    )?)))
}

/// Parse the files `--check` needs to prove TLS will come up.
pub fn server_config(cert_path: &str, key_path: &str) -> anyhow::Result<ServerConfig> {
    ensure_provider();
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("listen.tls: {e}"))
}

fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).map_err(|e| anyhow::anyhow!("listen.tls.cert ({path}): {e}"))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("listen.tls.cert ({path}): {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("listen.tls.cert ({path}) contains no certificates");
    }
    Ok(certs)
}

fn load_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let file = File::open(path).map_err(|e| anyhow::anyhow!("listen.tls.key ({path}): {e}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| anyhow::anyhow!("listen.tls.key ({path}): {e}"))?
        .ok_or_else(|| anyhow::anyhow!("listen.tls.key ({path}) contains no private key"))
}
