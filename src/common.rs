//! Common types and functions shared across client, nc, and server modules.
//!
//! This module provides shared functionality to avoid code duplication between
//! the different modes of qrelay.

use crate::cli::{ClientArgs, NcArgs};
use crate::error::{Error, Result};
use crate::tls::{
    build_client_config_ca, build_client_config_fingerprint, build_client_config_insecure,
    parse_fingerprint,
};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Buffer size for reading data from TCP, stdin, and QUIC streams.
pub const READ_BUFFER_SIZE: usize = 16 * 1024;

/// Security mode for TLS verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityMode {
    /// CA certificate validation (default or custom CA).
    Ca,
    /// Public key fingerprint validation.
    Fingerprint,
    /// No verification (insecure, development only).
    None,
}

/// Trait for arguments that can determine a security mode.
pub trait SecurityModeArgs {
    fn insecure_skip_verify(&self) -> bool;
    fn fingerprint(&self) -> Option<&str>;
}

impl SecurityModeArgs for ClientArgs {
    fn insecure_skip_verify(&self) -> bool {
        self.insecure_skip_verify
    }

    fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }
}

impl SecurityModeArgs for NcArgs {
    fn insecure_skip_verify(&self) -> bool {
        self.insecure_skip_verify
    }

    fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }
}

impl SecurityMode {
    /// Determines the security mode from arguments.
    pub fn from_args<T: SecurityModeArgs>(args: &T) -> Self {
        if args.insecure_skip_verify() {
            SecurityMode::None
        } else if args.fingerprint().is_some() {
            SecurityMode::Fingerprint
        } else {
            SecurityMode::Ca
        }
    }
}

/// Trait for arguments used to build TLS client configuration.
pub trait TlsClientArgs: SecurityModeArgs {
    fn ca(&self) -> Option<&Path>;
    fn alpn(&self) -> &str;
}

impl TlsClientArgs for ClientArgs {
    fn ca(&self) -> Option<&Path> {
        self.ca.as_deref()
    }

    fn alpn(&self) -> &str {
        &self.alpn
    }
}

impl TlsClientArgs for NcArgs {
    fn ca(&self) -> Option<&Path> {
        self.ca.as_deref()
    }

    fn alpn(&self) -> &str {
        &self.alpn
    }
}

/// Builds TLS client configuration based on arguments.
pub fn build_tls_config<T: TlsClientArgs>(args: &T) -> Result<rustls::ClientConfig> {
    let security_mode = SecurityMode::from_args(args);

    match security_mode {
        SecurityMode::None => build_client_config_insecure(args.alpn())
            .map_err(|e| Error::TlsVerificationFailed(e.to_string())),
        SecurityMode::Fingerprint => {
            let fp_str = args.fingerprint().unwrap();
            let fingerprint = parse_fingerprint(fp_str)
                .map_err(|e| Error::TlsVerificationFailed(e.to_string()))?;
            build_client_config_fingerprint(&fingerprint, args.alpn())
                .map_err(|e| Error::TlsVerificationFailed(e.to_string()))
        }
        SecurityMode::Ca => build_client_config_ca(args.ca(), args.alpn())
            .map_err(|e| Error::TlsVerificationFailed(e.to_string())),
    }
}

/// Parses a connect address string into a SocketAddr and extracts the host for SNI.
///
/// Uses a shared DNS resolver for efficiency when making multiple resolutions.
pub async fn parse_connect_address(
    connect: &str,
    sni: Option<&str>,
    resolver: &DnsResolver,
) -> Result<(SocketAddr, String)> {
    // Extract host and port
    let (host, port) = if let Some(colon_pos) = connect.rfind(':') {
        let host_part = &connect[..colon_pos];
        let port_part = &connect[colon_pos + 1..];

        // Handle IPv6 addresses in brackets
        let host = if host_part.starts_with('[') && host_part.ends_with(']') {
            &host_part[1..host_part.len() - 1]
        } else {
            host_part
        };

        let port: u16 = port_part
            .parse()
            .map_err(|_| Error::Config(format!("invalid port in address '{}'", connect)))?;

        (host.to_string(), port)
    } else {
        return Err(Error::Config(format!(
            "address must include port: '{}'",
            connect
        )));
    };

    // Resolve address asynchronously
    let addr = resolver.resolve(&host, port).await?;

    // Determine SNI hostname
    let sni_host = sni.map(|s| s.to_string()).unwrap_or(host);

    Ok((addr, sni_host))
}

/// Shared DNS resolver wrapper for reuse across multiple resolutions.
///
/// This addresses the review feedback about DNS resolver reuse.
pub struct DnsResolver {
    resolver: Arc<Mutex<Option<hickory_resolver::Resolver<hickory_resolver::name_server::TokioConnectionProvider>>>>,
}

impl DnsResolver {
    /// Creates a new DNS resolver.
    pub fn new() -> Self {
        Self {
            resolver: Arc::new(Mutex::new(None)),
        }
    }

    /// Resolves a hostname to a SocketAddr asynchronously using hickory-resolver.
    ///
    /// The resolver is lazily initialized and reused for subsequent resolutions.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr> {
        // First try parsing as IP address
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }

        // Lazily initialize the resolver
        let mut resolver_guard = self.resolver.lock().await;
        if resolver_guard.is_none() {
            let resolver = hickory_resolver::Resolver::builder_tokio()
                .map_err(|e| Error::Config(format!("failed to create DNS resolver: {}", e)))?
                .build();
            *resolver_guard = Some(resolver);
        }

        let resolver = resolver_guard.as_ref().unwrap();

        let response = resolver
            .lookup_ip(host)
            .await
            .map_err(|e| Error::Config(format!("failed to resolve '{}': {}", host, e)))?;

        response
            .iter()
            .next()
            .map(|ip| SocketAddr::new(ip, port))
            .ok_or_else(|| Error::Config(format!("no addresses found for '{}'", host)))
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Formats a duration in a human-readable format similar to Go's duration format.
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let nanos = d.subsec_nanos();

    if secs == 0 && nanos == 0 {
        return "0s".to_string();
    }

    let mut result = String::new();

    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let secs_remainder = secs % 60;

    if hours > 0 {
        result.push_str(&format!("{}h", hours));
    }
    if mins > 0 {
        result.push_str(&format!("{}m", mins));
    }
    if secs_remainder > 0 || (hours == 0 && mins == 0 && nanos == 0) {
        result.push_str(&format!("{}s", secs_remainder));
    } else if nanos > 0 && hours == 0 && mins == 0 && secs_remainder == 0 {
        let ms = nanos / 1_000_000;
        if ms > 0 {
            result.push_str(&format!("{}ms", ms));
        }
    }

    if result.is_empty() {
        "0s".to_string()
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_security_mode_from_args_default() {
        struct TestArgs {
            insecure: bool,
            fp: Option<String>,
        }

        impl SecurityModeArgs for TestArgs {
            fn insecure_skip_verify(&self) -> bool {
                self.insecure
            }

            fn fingerprint(&self) -> Option<&str> {
                self.fp.as_deref()
            }
        }

        let args = TestArgs {
            insecure: false,
            fp: None,
        };
        assert_eq!(SecurityMode::from_args(&args), SecurityMode::Ca);
    }

    #[test]
    fn test_security_mode_from_args_fingerprint() {
        struct TestArgs {
            insecure: bool,
            fp: Option<String>,
        }

        impl SecurityModeArgs for TestArgs {
            fn insecure_skip_verify(&self) -> bool {
                self.insecure
            }

            fn fingerprint(&self) -> Option<&str> {
                self.fp.as_deref()
            }
        }

        let args = TestArgs {
            insecure: false,
            fp: Some("aa:bb:cc".to_string()),
        };
        assert_eq!(SecurityMode::from_args(&args), SecurityMode::Fingerprint);
    }

    #[test]
    fn test_security_mode_from_args_insecure() {
        struct TestArgs {
            insecure: bool,
            fp: Option<String>,
        }

        impl SecurityModeArgs for TestArgs {
            fn insecure_skip_verify(&self) -> bool {
                self.insecure
            }

            fn fingerprint(&self) -> Option<&str> {
                self.fp.as_deref()
            }
        }

        let args = TestArgs {
            insecure: true,
            fp: None,
        };
        assert_eq!(SecurityMode::from_args(&args), SecurityMode::None);
    }

    #[test]
    fn test_security_mode_insecure_takes_precedence() {
        struct TestArgs {
            insecure: bool,
            fp: Option<String>,
        }

        impl SecurityModeArgs for TestArgs {
            fn insecure_skip_verify(&self) -> bool {
                self.insecure
            }

            fn fingerprint(&self) -> Option<&str> {
                self.fp.as_deref()
            }
        }

        let args = TestArgs {
            insecure: true,
            fp: Some("aa:bb:cc".to_string()),
        };
        assert_eq!(SecurityMode::from_args(&args), SecurityMode::None);
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(Duration::from_secs(10)), "10s");
        assert_eq!(format_duration(Duration::from_secs(3)), "3s");
    }

    #[test]
    fn test_format_duration_zero() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
    }

    #[test]
    fn test_format_duration_hours() {
        // 168h = 7 days (trailing zeros are omitted)
        assert_eq!(
            format_duration(Duration::from_secs(168 * 3600)),
            "168h"
        );
    }

    #[test]
    fn test_format_duration_mixed() {
        assert_eq!(
            format_duration(Duration::from_secs(3600 + 1800 + 10)),
            "1h30m10s"
        );
    }

    #[tokio::test]
    async fn test_dns_resolver_ip_address() {
        let resolver = DnsResolver::new();
        let addr = resolver.resolve("127.0.0.1", 8080).await.unwrap();
        assert_eq!(addr.ip(), std::net::Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(addr.port(), 8080);
    }

    #[tokio::test]
    async fn test_dns_resolver_ipv6() {
        let resolver = DnsResolver::new();
        let addr = resolver.resolve("::1", 8080).await.unwrap();
        assert_eq!(addr.ip(), std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(addr.port(), 8080);
    }

    #[tokio::test]
    async fn test_parse_connect_address_host_port() {
        let resolver = DnsResolver::new();
        let (addr, sni) = parse_connect_address("127.0.0.1:9443", None, &resolver)
            .await
            .unwrap();
        assert_eq!(addr.port(), 9443);
        assert_eq!(sni, "127.0.0.1");
    }

    #[tokio::test]
    async fn test_parse_connect_address_with_sni() {
        let resolver = DnsResolver::new();
        let (addr, sni) = parse_connect_address("127.0.0.1:9443", Some("example.com"), &resolver)
            .await
            .unwrap();
        assert_eq!(addr.port(), 9443);
        assert_eq!(sni, "example.com");
    }

    #[tokio::test]
    async fn test_parse_connect_address_ipv6() {
        let resolver = DnsResolver::new();
        let (addr, sni) = parse_connect_address("[::1]:9443", None, &resolver)
            .await
            .unwrap();
        assert_eq!(addr.port(), 9443);
        assert_eq!(sni, "::1");
    }

    #[tokio::test]
    async fn test_parse_connect_address_no_port() {
        let resolver = DnsResolver::new();
        let result = parse_connect_address("127.0.0.1", None, &resolver).await;
        assert!(result.is_err());
    }
}
