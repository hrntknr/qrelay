//! CLI definitions for qrelay.

use clap::{builder::PossibleValuesParser, Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;

/// Default ALPN protocol identifier.
pub const DEFAULT_ALPN: &str = "qrelay/1";

/// Default idle timeout in seconds.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 10;

/// Default keep-alive interval in seconds.
pub const DEFAULT_KEEP_ALIVE_SECS: u64 = 3;

/// Default reconnect interval in seconds.
pub const DEFAULT_RECONNECT_INTERVAL_SECS: u64 = 1;

/// Default max buffer bytes (64MB).
pub const DEFAULT_MAX_BUFFER_BYTES: u64 = 67_108_864;

/// Default resume max age (7 days in seconds).
pub const DEFAULT_RESUME_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Parse a duration from a human-readable string.
fn parse_duration(s: &str) -> Result<Duration, humantime::DurationError> {
    humantime::parse_duration(s)
}

/// Reconnectable, order-guaranteed, lossless byte stream TCP proxy.
#[derive(Debug, Parser)]
#[command(name = "qrelay")]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Log level (debug|info|warn|error)
    #[arg(long, global = true, default_value = "info", value_parser = PossibleValuesParser::new(["debug", "info", "warn", "error"]))]
    pub log_level: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start server-side proxy
    Server(ServerArgs),

    /// Start client-side proxy (TCP listen)
    Client(ClientArgs),

    /// stdin/stdout proxy (for SSH ProxyCommand)
    Nc(NcArgs),

    /// Show version information
    Version,
}

/// Arguments for the server subcommand.
#[derive(Debug, Parser)]
pub struct ServerArgs {
    /// QUIC listen address (e.g., :9443)
    #[arg(long)]
    pub listen: String,

    /// Backend TCP address (e.g., 127.0.0.1:22)
    #[arg(long)]
    pub backend: String,

    /// TLS certificate file path
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// TLS private key file path
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// ALPN protocol identifier
    #[arg(long, default_value = DEFAULT_ALPN)]
    pub alpn: String,

    /// QUIC idle timeout
    #[arg(long, value_parser = parse_duration, default_value = "10s")]
    pub idle_timeout: Duration,

    /// QUIC keep-alive interval (0 to disable)
    #[arg(long, value_parser = parse_duration, default_value = "3s")]
    pub keep_alive: Duration,

    /// Deep buffer limit in bytes
    #[arg(long, default_value_t = DEFAULT_MAX_BUFFER_BYTES)]
    pub max_buffer_bytes: u64,

    /// Session resume max age
    #[arg(long, value_parser = parse_duration, default_value = "168h")]
    pub resume_max_age: Duration,

    /// Configuration directory path
    #[arg(long)]
    pub config_dir: Option<PathBuf>,
}

/// Arguments for the client subcommand.
#[derive(Debug, Parser)]
pub struct ClientArgs {
    /// Local TCP listen address (e.g., 127.0.0.1:2222)
    #[arg(long)]
    pub listen: String,

    /// QUIC server address (e.g., server.example.com:9443)
    #[arg(long)]
    pub connect: String,

    /// TLS SNI hostname
    #[arg(long)]
    pub sni: Option<String>,

    /// Root CA certificate file path
    #[arg(long)]
    pub ca: Option<PathBuf>,

    /// Disable certificate verification (development only)
    #[arg(long, default_value_t = false)]
    pub insecure_skip_verify: bool,

    /// Public key fingerprint (SHA-256 hex)
    #[arg(long)]
    pub fingerprint: Option<String>,

    /// ALPN protocol identifier
    #[arg(long, default_value = DEFAULT_ALPN)]
    pub alpn: String,

    /// QUIC idle timeout
    #[arg(long, value_parser = parse_duration, default_value = "10s")]
    pub idle_timeout: Duration,

    /// QUIC keep-alive interval (0 to disable)
    #[arg(long, value_parser = parse_duration, default_value = "3s")]
    pub keep_alive: Duration,

    /// Reconnect interval
    #[arg(long, value_parser = parse_duration, default_value = "1s")]
    pub reconnect_interval: Duration,

    /// Deep buffer limit in bytes
    #[arg(long, default_value_t = DEFAULT_MAX_BUFFER_BYTES)]
    pub max_buffer_bytes: u64,
}

/// Arguments for the nc subcommand.
#[derive(Debug, Parser)]
pub struct NcArgs {
    /// QUIC server address (e.g., server.example.com:9443)
    #[arg(long)]
    pub connect: String,

    /// TLS SNI hostname
    #[arg(long)]
    pub sni: Option<String>,

    /// Root CA certificate file path
    #[arg(long)]
    pub ca: Option<PathBuf>,

    /// Disable certificate verification (development only)
    #[arg(long, default_value_t = false)]
    pub insecure_skip_verify: bool,

    /// Public key fingerprint (SHA-256 hex)
    #[arg(long)]
    pub fingerprint: Option<String>,

    /// ALPN protocol identifier
    #[arg(long, default_value = DEFAULT_ALPN)]
    pub alpn: String,

    /// QUIC idle timeout
    #[arg(long, value_parser = parse_duration, default_value = "10s")]
    pub idle_timeout: Duration,

    /// QUIC keep-alive interval (0 to disable)
    #[arg(long, value_parser = parse_duration, default_value = "3s")]
    pub keep_alive: Duration,

    /// Reconnect interval
    #[arg(long, value_parser = parse_duration, default_value = "1s")]
    pub reconnect_interval: Duration,

    /// Deep buffer limit in bytes
    #[arg(long, default_value_t = DEFAULT_MAX_BUFFER_BYTES)]
    pub max_buffer_bytes: u64,
}

/// Returns the default configuration directory.
///
/// - root (UID=0): `/etc/qrelay`
/// - others: `~/.qrelay`
pub fn default_config_dir() -> PathBuf {
    if is_root() {
        PathBuf::from("/etc/qrelay")
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".qrelay")
    }
}

/// Check if running as root.
fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: getuid() is a simple syscall that returns the real user ID.
        // It has no preconditions and always succeeds.
        unsafe { libc::getuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Build information for version command.
pub struct BuildInfo {
    pub version: &'static str,
    pub commit: &'static str,
    pub built: &'static str,
}

impl BuildInfo {
    /// Returns build information from environment variables or defaults.
    pub fn get() -> Self {
        Self {
            version: option_env!("CARGO_PKG_VERSION").unwrap_or("unknown"),
            commit: option_env!("QRELAY_COMMIT").unwrap_or("unknown"),
            built: option_env!("QRELAY_BUILD_DATE").unwrap_or("unknown"),
        }
    }

    /// Format version output.
    pub fn format(&self) -> String {
        format!(
            "qrelay version {}\n  commit: {}\n  built:  {}",
            self.version, self.commit, self.built
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_debug_assert() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_parse_server_minimal() {
        let cli = Cli::try_parse_from([
            "qrelay",
            "server",
            "--listen",
            ":9443",
            "--backend",
            "127.0.0.1:22",
        ])
        .unwrap();

        assert_eq!(cli.log_level, "info");
        match cli.command {
            Command::Server(args) => {
                assert_eq!(args.listen, ":9443");
                assert_eq!(args.backend, "127.0.0.1:22");
                assert_eq!(args.alpn, DEFAULT_ALPN);
                assert_eq!(args.idle_timeout, Duration::from_secs(10));
                assert_eq!(args.keep_alive, Duration::from_secs(3));
                assert_eq!(args.max_buffer_bytes, DEFAULT_MAX_BUFFER_BYTES);
                assert!(args.tls_cert.is_none());
                assert!(args.tls_key.is_none());
                assert!(args.config_dir.is_none());
            }
            _ => panic!("Expected Server command"),
        }
    }

    #[test]
    fn test_parse_server_full() {
        let cli = Cli::try_parse_from([
            "qrelay",
            "--log-level",
            "debug",
            "server",
            "--listen",
            ":9443",
            "--backend",
            "127.0.0.1:22",
            "--tls-cert",
            "/path/to/cert.pem",
            "--tls-key",
            "/path/to/key.pem",
            "--alpn",
            "custom/1",
            "--idle-timeout",
            "30s",
            "--keep-alive",
            "5s",
            "--max-buffer-bytes",
            "1000000",
            "--resume-max-age",
            "24h",
            "--config-dir",
            "/custom/config",
        ])
        .unwrap();

        assert_eq!(cli.log_level, "debug");
        match cli.command {
            Command::Server(args) => {
                assert_eq!(args.listen, ":9443");
                assert_eq!(args.backend, "127.0.0.1:22");
                assert_eq!(args.tls_cert, Some(PathBuf::from("/path/to/cert.pem")));
                assert_eq!(args.tls_key, Some(PathBuf::from("/path/to/key.pem")));
                assert_eq!(args.alpn, "custom/1");
                assert_eq!(args.idle_timeout, Duration::from_secs(30));
                assert_eq!(args.keep_alive, Duration::from_secs(5));
                assert_eq!(args.max_buffer_bytes, 1_000_000);
                assert_eq!(args.resume_max_age, Duration::from_secs(24 * 60 * 60));
                assert_eq!(args.config_dir, Some(PathBuf::from("/custom/config")));
            }
            _ => panic!("Expected Server command"),
        }
    }

    #[test]
    fn test_parse_client_minimal() {
        let cli = Cli::try_parse_from([
            "qrelay",
            "client",
            "--listen",
            "127.0.0.1:2222",
            "--connect",
            "server.example.com:9443",
        ])
        .unwrap();

        match cli.command {
            Command::Client(args) => {
                assert_eq!(args.listen, "127.0.0.1:2222");
                assert_eq!(args.connect, "server.example.com:9443");
                assert!(args.sni.is_none());
                assert!(args.ca.is_none());
                assert!(!args.insecure_skip_verify);
                assert!(args.fingerprint.is_none());
                assert_eq!(args.alpn, DEFAULT_ALPN);
                assert_eq!(args.reconnect_interval, Duration::from_secs(1));
            }
            _ => panic!("Expected Client command"),
        }
    }

    #[test]
    fn test_parse_client_full() {
        let cli = Cli::try_parse_from([
            "qrelay",
            "client",
            "--listen",
            "127.0.0.1:2222",
            "--connect",
            "server.example.com:9443",
            "--sni",
            "custom.example.com",
            "--ca",
            "/path/to/ca.pem",
            "--fingerprint",
            "aa:bb:cc:dd",
            "--alpn",
            "custom/1",
            "--idle-timeout",
            "20s",
            "--keep-alive",
            "10s",
            "--reconnect-interval",
            "5s",
            "--max-buffer-bytes",
            "1000000",
        ])
        .unwrap();

        match cli.command {
            Command::Client(args) => {
                assert_eq!(args.listen, "127.0.0.1:2222");
                assert_eq!(args.connect, "server.example.com:9443");
                assert_eq!(args.sni, Some("custom.example.com".to_string()));
                assert_eq!(args.ca, Some(PathBuf::from("/path/to/ca.pem")));
                assert_eq!(args.fingerprint, Some("aa:bb:cc:dd".to_string()));
                assert_eq!(args.alpn, "custom/1");
                assert_eq!(args.idle_timeout, Duration::from_secs(20));
                assert_eq!(args.keep_alive, Duration::from_secs(10));
                assert_eq!(args.reconnect_interval, Duration::from_secs(5));
                assert_eq!(args.max_buffer_bytes, 1_000_000);
            }
            _ => panic!("Expected Client command"),
        }
    }

    #[test]
    fn test_parse_client_insecure() {
        let cli = Cli::try_parse_from([
            "qrelay",
            "client",
            "--listen",
            "127.0.0.1:2222",
            "--connect",
            "server.example.com:9443",
            "--insecure-skip-verify",
        ])
        .unwrap();

        match cli.command {
            Command::Client(args) => {
                assert!(args.insecure_skip_verify);
            }
            _ => panic!("Expected Client command"),
        }
    }

    #[test]
    fn test_parse_nc_minimal() {
        let cli =
            Cli::try_parse_from(["qrelay", "nc", "--connect", "server.example.com:9443"]).unwrap();

        match cli.command {
            Command::Nc(args) => {
                assert_eq!(args.connect, "server.example.com:9443");
                assert!(args.sni.is_none());
                assert!(args.ca.is_none());
                assert!(!args.insecure_skip_verify);
                assert!(args.fingerprint.is_none());
                assert_eq!(args.alpn, DEFAULT_ALPN);
            }
            _ => panic!("Expected Nc command"),
        }
    }

    #[test]
    fn test_parse_nc_full() {
        let cli = Cli::try_parse_from([
            "qrelay",
            "nc",
            "--connect",
            "server.example.com:9443",
            "--sni",
            "custom.example.com",
            "--ca",
            "/path/to/ca.pem",
            "--fingerprint",
            "aa:bb:cc:dd",
            "--alpn",
            "custom/1",
            "--idle-timeout",
            "20s",
            "--keep-alive",
            "10s",
            "--reconnect-interval",
            "5s",
            "--max-buffer-bytes",
            "1000000",
        ])
        .unwrap();

        match cli.command {
            Command::Nc(args) => {
                assert_eq!(args.connect, "server.example.com:9443");
                assert_eq!(args.sni, Some("custom.example.com".to_string()));
                assert_eq!(args.ca, Some(PathBuf::from("/path/to/ca.pem")));
                assert_eq!(args.fingerprint, Some("aa:bb:cc:dd".to_string()));
                assert_eq!(args.alpn, "custom/1");
                assert_eq!(args.idle_timeout, Duration::from_secs(20));
                assert_eq!(args.keep_alive, Duration::from_secs(10));
                assert_eq!(args.reconnect_interval, Duration::from_secs(5));
                assert_eq!(args.max_buffer_bytes, 1_000_000);
            }
            _ => panic!("Expected Nc command"),
        }
    }

    #[test]
    fn test_parse_version() {
        let cli = Cli::try_parse_from(["qrelay", "version"]).unwrap();
        assert!(matches!(cli.command, Command::Version));
    }

    #[test]
    fn test_parse_global_log_level() {
        let cli = Cli::try_parse_from([
            "qrelay",
            "--log-level",
            "warn",
            "nc",
            "--connect",
            "server:9443",
        ])
        .unwrap();
        assert_eq!(cli.log_level, "warn");
    }

    #[test]
    fn test_server_missing_required() {
        let result = Cli::try_parse_from(["qrelay", "server", "--listen", ":9443"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_missing_required() {
        let result = Cli::try_parse_from(["qrelay", "client", "--listen", "127.0.0.1:2222"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_nc_missing_required() {
        let result = Cli::try_parse_from(["qrelay", "nc"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_duration_parsing() {
        let cli = Cli::try_parse_from([
            "qrelay",
            "server",
            "--listen",
            ":9443",
            "--backend",
            "127.0.0.1:22",
            "--idle-timeout",
            "1m30s",
            "--keep-alive",
            "500ms",
        ])
        .unwrap();

        match cli.command {
            Command::Server(args) => {
                assert_eq!(args.idle_timeout, Duration::from_secs(90));
                assert_eq!(args.keep_alive, Duration::from_millis(500));
            }
            _ => panic!("Expected Server command"),
        }
    }

    #[test]
    fn test_build_info_format() {
        let info = BuildInfo {
            version: "1.0.0",
            commit: "abc1234",
            built: "2025-01-01T00:00:00Z",
        };
        let output = info.format();
        assert!(output.contains("qrelay version 1.0.0"));
        assert!(output.contains("commit: abc1234"));
        assert!(output.contains("built:  2025-01-01T00:00:00Z"));
    }

    #[test]
    fn test_default_config_dir() {
        let dir = default_config_dir();
        // Should return a valid path
        assert!(!dir.as_os_str().is_empty());
    }
}
