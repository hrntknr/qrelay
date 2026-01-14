//! Error types for qrelay.

use thiserror::Error;

/// Exit codes for client and nc subcommands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// Normal exit
    Success = 0,
    /// Listen failed
    ListenFailed = 10,
    /// QUIC connection failed
    QuicConnectionFailed = 11,
    /// TLS verification failed
    TlsVerificationFailed = 12,
    /// Buffer limit exceeded
    BufferLimitExceeded = 20,
    /// Resume rejected
    ResumeRejected = 21,
}

impl From<ExitCode> for i32 {
    fn from(code: ExitCode) -> Self {
        code as i32
    }
}

/// Main error type for qrelay.
#[derive(Debug, Error)]
pub enum Error {
    #[error("listen failed: {0}")]
    ListenFailed(String),

    #[error("QUIC connection failed: {0}")]
    QuicConnectionFailed(String),

    #[error("TLS verification failed: {0}")]
    TlsVerificationFailed(String),

    #[error("buffer limit exceeded")]
    BufferLimitExceeded,

    #[error("resume rejected: {0}")]
    ResumeRejected(String),

    #[error("session closed: {0}")]
    SessionClosed(String),

    #[error("QUIC disconnected: {0}")]
    QuicDisconnected(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("configuration error: {0}")]
    Config(String),
}

impl Error {
    /// Returns the exit code for this error.
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Error::ListenFailed(_) => ExitCode::ListenFailed,
            Error::QuicConnectionFailed(_) => ExitCode::QuicConnectionFailed,
            Error::TlsVerificationFailed(_) => ExitCode::TlsVerificationFailed,
            Error::BufferLimitExceeded => ExitCode::BufferLimitExceeded,
            Error::ResumeRejected(_) => ExitCode::ResumeRejected,
            Error::SessionClosed(_) => ExitCode::Success,
            Error::QuicDisconnected(_) => ExitCode::QuicConnectionFailed,
            Error::Io(_) => ExitCode::ListenFailed,
            Error::Config(_) => ExitCode::ListenFailed,
        }
    }
}

/// Result type alias for qrelay operations.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_closed_returns_success_exit_code() {
        let err = Error::SessionClosed("peer closed connection".to_string());
        assert_eq!(err.exit_code(), ExitCode::Success);
    }

    #[test]
    fn session_closed_display_includes_reason() {
        let reason = "graceful shutdown";
        let err = Error::SessionClosed(reason.to_string());
        assert!(err.to_string().contains(reason));
    }
}
