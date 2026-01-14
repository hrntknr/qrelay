//! TLS/certificate handling for qrelay.
//!
//! This module provides:
//! - Self-signed certificate generation (ECDSA P-256)
//! - Certificate loading and saving
//! - SHA-256 fingerprint computation and parsing
//! - rustls configuration builders for server and client modes

use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

/// Certificate and key file names for auto-generated certificates.
const CERT_FILENAME: &str = "cert.pem";
const KEY_FILENAME: &str = "key.pem";

/// Error type for TLS operations.
#[derive(Debug, Error)]
pub enum TlsError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("certificate generation failed: {0}")]
    CertificateGeneration(String),

    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),

    #[error("invalid fingerprint: {0}")]
    InvalidFingerprint(String),

    #[error("TLS configuration error: {0}")]
    TlsConfig(String),
}

/// Result type for TLS operations.
pub type TlsResult<T> = std::result::Result<T, TlsError>;

/// Certificate and key pair with computed fingerprint.
#[derive(Clone)]
pub struct CertKeyPair {
    /// Certificate chain in DER format.
    pub cert_der: Vec<Vec<u8>>,
    /// Private key in DER format.
    pub key_der: Vec<u8>,
    /// SHA-256 fingerprint of the certificate (colon-separated hex).
    pub fingerprint: String,
}

/// Generates a self-signed ECDSA P-256 certificate.
///
/// Returns a tuple of (certificate PEM, private key PEM, fingerprint).
pub fn generate_self_signed_cert() -> TlsResult<(String, String, String)> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| TlsError::CertificateGeneration(e.to_string()))?;

    let mut params = CertificateParams::new(vec!["localhost".to_string()])
        .map_err(|e| TlsError::CertificateGeneration(e.to_string()))?;

    // Set validity period to 1 year from now
    let now = time::OffsetDateTime::now_utc();
    let one_year_later = now + time::Duration::days(365);
    params.not_before = now;
    params.not_after = one_year_later;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TlsError::CertificateGeneration(e.to_string()))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let cert_der = cert.der().to_vec();
    let fingerprint = compute_fingerprint(&cert_der);

    Ok((cert_pem, key_pem, fingerprint))
}

/// Loads a certificate and key from the config directory, or generates new ones if not present.
/// Returns (CertKeyPair, bool) where bool indicates if the certificate was newly generated.
pub fn load_or_generate_cert(config_dir: &Path) -> TlsResult<(CertKeyPair, bool)> {
    let cert_path = config_dir.join(CERT_FILENAME);
    let key_path = config_dir.join(KEY_FILENAME);

    if cert_path.exists() && key_path.exists() {
        Ok((load_cert_key(&cert_path, &key_path)?, false))
    } else {
        // Ensure config directory exists
        fs::create_dir_all(config_dir)?;

        let (cert_pem, key_pem, fingerprint) = generate_self_signed_cert()?;

        fs::write(&cert_path, &cert_pem)?;
        fs::write(&key_path, &key_pem)?;

        // Set private key file permissions to 0600 (owner read/write only) on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&key_path, permissions)?;
        }

        let cert_der = parse_cert_pem(&cert_pem)?;
        let key_der = parse_key_pem(&key_pem)?;

        Ok((
            CertKeyPair {
                cert_der,
                key_der,
                fingerprint,
            },
            true,
        ))
    }
}

/// Loads a certificate and key from the specified paths.
pub fn load_cert_key(cert_path: &Path, key_path: &Path) -> TlsResult<CertKeyPair> {
    let cert_pem = fs::read_to_string(cert_path)?;
    let key_pem = fs::read_to_string(key_path)?;

    let cert_der = parse_cert_pem(&cert_pem)?;
    let key_der = parse_key_pem(&key_pem)?;

    let fingerprint = if !cert_der.is_empty() {
        compute_fingerprint(&cert_der[0])
    } else {
        return Err(TlsError::InvalidCertificate(
            "no certificates found".to_string(),
        ));
    };

    Ok(CertKeyPair {
        cert_der,
        key_der,
        fingerprint,
    })
}

/// Loads a certificate and key from the specified paths, or generates new ones if not present.
/// Returns (CertKeyPair, was_generated).
pub fn load_or_generate_cert_at_paths(
    cert_path: &Path,
    key_path: &Path,
) -> TlsResult<(CertKeyPair, bool)> {
    if cert_path.exists() && key_path.exists() {
        Ok((load_cert_key(cert_path, key_path)?, false))
    } else {
        // Ensure parent directories exist
        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let (cert_pem, key_pem, fingerprint) = generate_self_signed_cert()?;

        fs::write(cert_path, &cert_pem)?;
        fs::write(key_path, &key_pem)?;

        // Set private key file permissions to 0600 (owner read/write only) on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(0o600);
            fs::set_permissions(key_path, permissions)?;
        }

        let cert_der = parse_cert_pem(&cert_pem)?;
        let key_der = parse_key_pem(&key_pem)?;

        Ok((
            CertKeyPair {
                cert_der,
                key_der,
                fingerprint,
            },
            true,
        ))
    }
}

/// Parses PEM-encoded certificates into DER format.
fn parse_cert_pem(pem: &str) -> TlsResult<Vec<Vec<u8>>> {
    let mut reader = BufReader::new(pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::InvalidCertificate(e.to_string()))?;

    if certs.is_empty() {
        return Err(TlsError::InvalidCertificate(
            "no certificates found in PEM".to_string(),
        ));
    }

    Ok(certs.into_iter().map(|c| c.to_vec()).collect())
}

/// Parses a PEM-encoded private key into DER format.
fn parse_key_pem(pem: &str) -> TlsResult<Vec<u8>> {
    let mut reader = BufReader::new(pem.as_bytes());

    // Try to read any private key format
    loop {
        match rustls_pemfile::read_one(&mut reader)
            .map_err(|e| TlsError::InvalidCertificate(e.to_string()))?
        {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => {
                return Ok(key.secret_pkcs1_der().to_vec());
            }
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => {
                return Ok(key.secret_pkcs8_der().to_vec());
            }
            Some(rustls_pemfile::Item::Sec1Key(key)) => {
                return Ok(key.secret_sec1_der().to_vec());
            }
            Some(_) => continue, // Skip other items (certificates, etc.)
            None => {
                return Err(TlsError::InvalidCertificate(
                    "no private key found in PEM".to_string(),
                ))
            }
        }
    }
}

/// Computes the SHA-256 fingerprint of a DER-encoded certificate.
///
/// Returns the fingerprint in colon-separated lowercase hex format.
pub fn compute_fingerprint(cert_der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let hash = hasher.finalize();
    format_fingerprint(&hash.into())
}

/// Parses a fingerprint string in either colon-separated or continuous hex format.
///
/// Both formats are accepted (case-insensitive):
/// - Colon-separated: `aa:bb:cc:dd:...` (95 characters for 32 bytes)
/// - Continuous hex: `aabbccdd...` (64 characters)
pub fn parse_fingerprint(s: &str) -> TlsResult<[u8; 32]> {
    let s = s.trim();

    // Determine format based on presence of colons
    let hex_str = if s.contains(':') {
        // Colon-separated format
        if s.len() != 95 {
            return Err(TlsError::InvalidFingerprint(format!(
                "colon-separated fingerprint must be 95 characters, got {}",
                s.len()
            )));
        }
        // Remove colons and validate format
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 32 {
            return Err(TlsError::InvalidFingerprint(format!(
                "expected 32 colon-separated bytes, got {}",
                parts.len()
            )));
        }
        for (i, part) in parts.iter().enumerate() {
            if part.len() != 2 {
                return Err(TlsError::InvalidFingerprint(format!(
                    "byte {} has invalid length: expected 2, got {}",
                    i,
                    part.len()
                )));
            }
        }
        s.replace(':', "")
    } else {
        // Continuous hex format
        if s.len() != 64 {
            return Err(TlsError::InvalidFingerprint(format!(
                "continuous hex fingerprint must be 64 characters, got {}",
                s.len()
            )));
        }
        s.to_string()
    };

    // Parse hex string into bytes
    let mut result = [0u8; 32];
    for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
        let hex_pair = std::str::from_utf8(chunk)
            .map_err(|_| TlsError::InvalidFingerprint("invalid UTF-8 in fingerprint".to_string()))?;
        result[i] = u8::from_str_radix(hex_pair, 16).map_err(|_| {
            TlsError::InvalidFingerprint(format!("invalid hex character in fingerprint: {}", hex_pair))
        })?;
    }

    Ok(result)
}

/// Formats a fingerprint as colon-separated lowercase hex.
pub fn format_fingerprint(bytes: &[u8; 32]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Builds a server TLS configuration.
pub fn build_server_config(cert_key: &CertKeyPair, alpn: &str) -> TlsResult<ServerConfig> {
    let certs: Vec<CertificateDer<'static>> = cert_key
        .cert_der
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect();

    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert_key.key_der.clone()));

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::TlsConfig(e.to_string()))?;

    config.alpn_protocols = vec![alpn.as_bytes().to_vec()];

    Ok(config)
}

/// Builds a client TLS configuration using CA certificate validation.
pub fn build_client_config_ca(ca_path: Option<&Path>, alpn: &str) -> TlsResult<ClientConfig> {
    let root_store = if let Some(path) = ca_path {
        // Load custom CA certificate
        let ca_pem = fs::read_to_string(path)?;
        let certs = parse_cert_pem(&ca_pem)?;

        let mut store = RootCertStore::empty();
        for cert in certs {
            store
                .add(CertificateDer::from(cert))
                .map_err(|e| TlsError::InvalidCertificate(e.to_string()))?;
        }
        store
    } else {
        // Use system root certificates
        let mut store = RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        store
    };

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.alpn_protocols = vec![alpn.as_bytes().to_vec()];

    Ok(config)
}

/// Builds a client TLS configuration using fingerprint verification.
pub fn build_client_config_fingerprint(
    fingerprint: &[u8; 32],
    alpn: &str,
) -> TlsResult<ClientConfig> {
    let verifier = FingerprintVerifier::new(*fingerprint);

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    config.alpn_protocols = vec![alpn.as_bytes().to_vec()];

    Ok(config)
}

/// Builds a client TLS configuration with no certificate verification (insecure, for development).
pub fn build_client_config_insecure(alpn: &str) -> TlsResult<ClientConfig> {
    tracing::warn!(
        "TLS certificate verification is disabled. This is insecure and should only be used for development."
    );
    let verifier = InsecureVerifier;

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    config.alpn_protocols = vec![alpn.as_bytes().to_vec()];

    Ok(config)
}

/// Custom certificate verifier that checks the certificate's SHA-256 fingerprint.
#[derive(Debug)]
struct FingerprintVerifier {
    expected: [u8; 32],
}

impl FingerprintVerifier {
    fn new(expected: [u8; 32]) -> Self {
        Self { expected }
    }
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let hash: [u8; 32] = hasher.finalize().into();

        if hash == self.expected {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "certificate fingerprint mismatch: expected {}, got {}",
                format_fingerprint(&self.expected),
                format_fingerprint(&hash)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Insecure certificate verifier that accepts any certificate (for development only).
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Once;
    use tempfile::tempdir;

    static INIT: Once = Once::new();

    /// Initialize the crypto provider for tests.
    fn init_crypto() {
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn test_generate_self_signed_cert() {
        let (cert_pem, key_pem, fingerprint) = generate_self_signed_cert().unwrap();

        // Verify PEM format
        assert!(cert_pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert_pem.contains("-----END CERTIFICATE-----"));
        assert!(key_pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(key_pem.contains("-----END PRIVATE KEY-----"));

        // Verify fingerprint format (colon-separated, 95 chars)
        assert_eq!(fingerprint.len(), 95);
        assert_eq!(fingerprint.matches(':').count(), 31);
    }

    #[test]
    fn test_load_or_generate_cert_creates_new() {
        let dir = tempdir().unwrap();
        let (result, generated) = load_or_generate_cert(dir.path()).unwrap();

        // Verify files were created
        assert!(dir.path().join(CERT_FILENAME).exists());
        assert!(dir.path().join(KEY_FILENAME).exists());

        // Verify cert_der is non-empty
        assert!(!result.cert_der.is_empty());
        assert!(!result.key_der.is_empty());
        assert_eq!(result.fingerprint.len(), 95);
        assert!(generated);
    }

    #[cfg(unix)]
    #[test]
    fn test_load_or_generate_cert_sets_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let _ = load_or_generate_cert(dir.path()).unwrap();

        let key_path = dir.path().join(KEY_FILENAME);
        let metadata = fs::metadata(&key_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;

        // Verify private key has 0600 permissions (owner read/write only)
        assert_eq!(mode, 0o600, "Expected key file permissions 0600, got {:o}", mode);
    }

    #[test]
    fn test_load_or_generate_cert_loads_existing() {
        let dir = tempdir().unwrap();

        // First call creates the certificate
        let (first, generated1) = load_or_generate_cert(dir.path()).unwrap();
        assert!(generated1);

        // Second call loads the existing certificate
        let (second, generated2) = load_or_generate_cert(dir.path()).unwrap();
        assert!(!generated2);

        // Fingerprints should match
        assert_eq!(first.fingerprint, second.fingerprint);
    }

    #[test]
    fn test_load_cert_key() {
        let dir = tempdir().unwrap();
        let (cert_pem, key_pem, expected_fingerprint) = generate_self_signed_cert().unwrap();

        let cert_path = dir.path().join("test.crt");
        let key_path = dir.path().join("test.key");

        fs::write(&cert_path, &cert_pem).unwrap();
        fs::write(&key_path, &key_pem).unwrap();

        let result = load_cert_key(&cert_path, &key_path).unwrap();
        assert_eq!(result.fingerprint, expected_fingerprint);
    }

    #[test]
    fn test_compute_fingerprint() {
        let data = b"test certificate data";
        let fingerprint = compute_fingerprint(data);

        // Verify format
        assert_eq!(fingerprint.len(), 95);
        assert_eq!(fingerprint.matches(':').count(), 31);

        // Verify determinism
        let fingerprint2 = compute_fingerprint(data);
        assert_eq!(fingerprint, fingerprint2);
    }

    #[test]
    fn test_parse_fingerprint_colon_separated() {
        let fp = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";
        let result = parse_fingerprint(fp).unwrap();

        assert_eq!(result[0], 0xaa);
        assert_eq!(result[1], 0xbb);
        assert_eq!(result[31], 0x99);
    }

    #[test]
    fn test_parse_fingerprint_continuous_hex() {
        let fp = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let result = parse_fingerprint(fp).unwrap();

        assert_eq!(result[0], 0xaa);
        assert_eq!(result[1], 0xbb);
        assert_eq!(result[31], 0x99);
    }

    #[test]
    fn test_parse_fingerprint_case_insensitive() {
        let lower = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let upper = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
        let mixed = "AaBbCcDdEeFf00112233445566778899aAbBcCdDeEfF00112233445566778899";

        let result_lower = parse_fingerprint(lower).unwrap();
        let result_upper = parse_fingerprint(upper).unwrap();
        let result_mixed = parse_fingerprint(mixed).unwrap();

        assert_eq!(result_lower, result_upper);
        assert_eq!(result_lower, result_mixed);
    }

    #[test]
    fn test_parse_fingerprint_invalid_length() {
        // Too short continuous hex
        let result = parse_fingerprint("aabbcc");
        assert!(result.is_err());

        // Too long continuous hex
        let result = parse_fingerprint("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aa");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_fingerprint_invalid_hex() {
        let result = parse_fingerprint("gghhiijjkkllmmnnoopp00112233445566778899aabbccddeeff00112233445566");
        assert!(result.is_err());
    }

    #[test]
    fn test_format_fingerprint() {
        let bytes: [u8; 32] = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
        ];
        let result = format_fingerprint(&bytes);

        assert_eq!(
            result,
            "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"
        );
    }

    #[test]
    fn test_format_parse_roundtrip() {
        let bytes: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ];
        let formatted = format_fingerprint(&bytes);
        let parsed = parse_fingerprint(&formatted).unwrap();

        assert_eq!(bytes, parsed);
    }

    #[test]
    fn test_build_server_config() {
        init_crypto();
        let (cert_pem, key_pem, fingerprint) = generate_self_signed_cert().unwrap();
        let cert_der = parse_cert_pem(&cert_pem).unwrap();
        let key_der = parse_key_pem(&key_pem).unwrap();

        let cert_key = CertKeyPair {
            cert_der,
            key_der,
            fingerprint,
        };

        let config = build_server_config(&cert_key, "qrelay/1").unwrap();
        assert_eq!(config.alpn_protocols, vec![b"qrelay/1".to_vec()]);
    }

    #[test]
    fn test_build_client_config_ca_default() {
        init_crypto();
        let config = build_client_config_ca(None, "qrelay/1").unwrap();
        assert_eq!(config.alpn_protocols, vec![b"qrelay/1".to_vec()]);
    }

    #[test]
    fn test_build_client_config_fingerprint() {
        init_crypto();
        let fingerprint: [u8; 32] = [0; 32];
        let config = build_client_config_fingerprint(&fingerprint, "qrelay/1").unwrap();
        assert_eq!(config.alpn_protocols, vec![b"qrelay/1".to_vec()]);
    }

    #[test]
    fn test_build_client_config_insecure() {
        init_crypto();
        let config = build_client_config_insecure("qrelay/1").unwrap();
        assert_eq!(config.alpn_protocols, vec![b"qrelay/1".to_vec()]);
    }

    #[test]
    fn test_load_or_generate_cert_at_paths_generates_new() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("custom.crt");
        let key_path = dir.path().join("custom.key");

        // Files don't exist, should generate
        let (cert_key, generated) = load_or_generate_cert_at_paths(&cert_path, &key_path).unwrap();
        assert!(generated);
        assert!(cert_path.exists());
        assert!(key_path.exists());
        assert!(!cert_key.fingerprint.is_empty());
    }

    #[test]
    fn test_load_or_generate_cert_at_paths_loads_existing() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("custom.crt");
        let key_path = dir.path().join("custom.key");

        // First call generates
        let (first, generated1) = load_or_generate_cert_at_paths(&cert_path, &key_path).unwrap();
        assert!(generated1);

        // Second call loads existing
        let (second, generated2) = load_or_generate_cert_at_paths(&cert_path, &key_path).unwrap();
        assert!(!generated2);
        assert_eq!(first.fingerprint, second.fingerprint);
    }

    #[cfg(unix)]
    #[test]
    fn test_load_or_generate_cert_at_paths_sets_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("custom.crt");
        let key_path = dir.path().join("custom.key");

        let _ = load_or_generate_cert_at_paths(&cert_path, &key_path).unwrap();

        let metadata = fs::metadata(&key_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
