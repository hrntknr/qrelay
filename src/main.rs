//! qrelay - Reconnectable, order-guaranteed, lossless byte stream TCP proxy.

use clap::Parser;
use qrelay::{run_client, run_nc, run_server, BuildInfo, Cli, Command, Error};
use tracing_subscriber::EnvFilter;

fn main() {
    let cli = Cli::parse();

    // Initialize logging
    // For nc mode, default to "error" level to avoid interfering with stdout
    let log_level = if matches!(cli.command, Command::Nc(_)) && cli.log_level == "info" {
        "error".to_string()
    } else {
        cli.log_level.clone()
    };
    let filter = EnvFilter::try_new(&log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    // Initialize the crypto provider
    if let Err(e) = rustls::crypto::ring::default_provider().install_default() {
        tracing::warn!("failed to install default crypto provider (may already be installed): {:?}", e);
    }

    match cli.command {
        Command::Server(args) => {
            tracing::info!("Server command received");
            tracing::debug!(?args, "Server arguments");

            let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            if let Err(e) = runtime.block_on(run_server(&args)) {
                tracing::error!(error = %e, "server error");
                std::process::exit(1);
            }
        }
        Command::Client(args) => {
            tracing::info!("Client command received");
            tracing::debug!(?args, "Client arguments");

            let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            if let Err(e) = runtime.block_on(run_client(&args)) {
                tracing::error!(error = %e, "client error");
                let exit_code = match &e {
                    Error::ListenFailed(_) => 10,
                    Error::QuicConnectionFailed(_) => 11,
                    Error::TlsVerificationFailed(_) => 12,
                    Error::BufferLimitExceeded => 20,
                    Error::ResumeRejected(_) => 21,
                    _ => 1,
                };
                std::process::exit(exit_code);
            }
        }
        Command::Nc(args) => {
            let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            if let Err(e) = runtime.block_on(run_nc(&args)) {
                tracing::error!(error = %e, "nc error");
                let exit_code = match &e {
                    Error::QuicConnectionFailed(_) => 11,
                    Error::TlsVerificationFailed(_) => 12,
                    Error::BufferLimitExceeded => 20,
                    Error::ResumeRejected(_) => 21,
                    _ => 1,
                };
                std::process::exit(exit_code);
            }
        }
        Command::Version => {
            let info = BuildInfo::get();
            println!("{}", info.format());
        }
    }
}
