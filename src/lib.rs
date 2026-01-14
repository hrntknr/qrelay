//! qrelay - Reconnectable, order-guaranteed, lossless byte stream TCP proxy.
//!
//! This crate provides a TCP proxy that uses QUIC for proxy-to-proxy communication,
//! enabling reconnection support, connection migration, and NAT rebinding tolerance.

pub mod buffer;
pub mod cli;
pub mod client;
pub mod common;
pub mod error;
pub mod nc;
pub mod protocol;
pub mod server;
pub mod session;
pub mod tls;

pub use buffer::{BufferError, BufferResult, RecvBuffer, SendBuffer, SessionState, DEFAULT_MAX_BUFFER_BYTES};
pub use cli::{BuildInfo, Cli, ClientArgs, Command, NcArgs, ServerArgs};
pub use client::run_client;
pub use common::{
    build_tls_config, format_duration, parse_connect_address, DnsResolver, SecurityMode,
    SecurityModeArgs, TlsClientArgs, READ_BUFFER_SIZE,
};
pub use error::{Error, ExitCode, Result};
pub use nc::run_nc;
pub use protocol::{decode_varint, encode_varint, Frame, ProtocolError, ProtocolResult};
pub use server::run_server;
pub use session::{BackendStream, Session, SessionManager, SESSION_ID_SIZE};
pub use tls::{
    build_client_config_ca, build_client_config_fingerprint, build_client_config_insecure,
    build_server_config, compute_fingerprint, format_fingerprint, generate_self_signed_cert,
    load_cert_key, load_or_generate_cert, parse_fingerprint, CertKeyPair, TlsError, TlsResult,
};
