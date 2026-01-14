//! Server mode implementation for qrelay.
//!
//! This module implements the QUIC server that accepts connections and relays
//! data to a backend TCP service.

use bytes::{Bytes, BytesMut};
use quinn::{Endpoint, RecvStream, SendStream, ServerConfig as QuinnServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, Mutex};

use crate::buffer::SessionState;
use crate::cli::{default_config_dir, ServerArgs};
use crate::common::{format_duration, READ_BUFFER_SIZE};
use crate::error::{Error, Result};
use crate::protocol::Frame;
use crate::session::{BackendStream, SessionManager, SESSION_ID_SIZE};
use crate::tls::{build_server_config, load_cert_key, load_or_generate_cert, CertKeyPair};
use tokio::sync::Mutex as TokioMutex;

/// Runs the qrelay server.
pub async fn run_server(args: &ServerArgs) -> Result<()> {
    // Load or generate TLS certificate
    let (cert_key, cert_auto_generated, config_path) = load_tls_config(args)?;

    // Build QUIC server config
    let tls_config = build_server_config(&cert_key, &args.alpn)
        .map_err(|e| Error::Config(format!("failed to build TLS config: {}", e)))?;

    let mut quinn_config = QuinnServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| Error::Config(format!("failed to create QUIC config: {}", e)))?,
    ));

    // Configure transport parameters
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(
        args.idle_timeout
            .try_into()
            .map_err(|_| Error::Config("idle timeout too large".to_string()))?,
    ));
    if !args.keep_alive.is_zero() {
        transport_config.keep_alive_interval(Some(args.keep_alive));
    }
    quinn_config.transport_config(Arc::new(transport_config));

    // Parse listen address
    let listen_addr = parse_listen_address(&args.listen)?;

    // Create QUIC endpoint
    let endpoint = Endpoint::server(quinn_config, listen_addr)
        .map_err(|e| Error::ListenFailed(e.to_string()))?;

    // Print startup message
    print_startup_message(args, &cert_key, cert_auto_generated, config_path.as_deref());

    // Create session manager
    let session_manager = Arc::new(Mutex::new(SessionManager::new(args.resume_max_age)));

    // Create shutdown signal broadcaster
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Spawn cleanup task with shutdown support
    let cleanup_manager = Arc::clone(&session_manager);
    let mut cleanup_shutdown_rx = shutdown_tx.subscribe();
    let cleanup_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    cleanup_manager.lock().await.cleanup_expired();
                }
                _ = cleanup_shutdown_rx.recv() => {
                    tracing::debug!("cleanup task received shutdown signal");
                    break;
                }
            }
        }
    });

    // Accept connections
    tracing::info!("Server listening on {}", listen_addr);

    // Track active connection tasks
    let active_connections = Arc::new(Mutex::new(Vec::new()));

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                match incoming {
                    Some(incoming) => {
                        let backend = args.backend.clone();
                        let max_buffer_bytes = args.max_buffer_bytes;
                        let session_manager = Arc::clone(&session_manager);
                        let conn_shutdown_rx = shutdown_tx.subscribe();

                        let handle = tokio::spawn(async move {
                            match incoming.await {
                                Ok(connection) => {
                                    let remote_addr = connection.remote_address();
                                    tracing::info!(?remote_addr, "new QUIC connection accepted");

                                    // Run connection handling with shutdown support
                                    // Shutdown signal is passed to run_relay for graceful CLOSE on existing stream
                                    let result = handle_connection(
                                        connection.clone(),
                                        &backend,
                                        max_buffer_bytes,
                                        session_manager,
                                        Some(conn_shutdown_rx),
                                    ).await;

                                    match &result {
                                        Ok(_) => {}
                                        Err(Error::SessionClosed(reason)) => {
                                            tracing::info!(?remote_addr, reason, "session closed normally");
                                        }
                                        Err(Error::QuicDisconnected(reason)) => {
                                            tracing::info!(?remote_addr, reason, "QUIC disconnected, waiting for resume");
                                        }
                                        Err(e) => {
                                            tracing::error!(?remote_addr, error = %e, "connection error");
                                        }
                                    }

                                    // Close the QUIC connection after relay ends
                                    // SessionClosed の場合はクライアント側からcloseしてもらう
                                    // （CLOSEフレームの確実な到達のため）
                                    if !matches!(result, Err(Error::SessionClosed(_))) {
                                        connection.close(0u32.into(), b"session ended");
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "failed to accept connection");
                                }
                            }
                        });

                        active_connections.lock().await.push(handle);
                    }
                    None => {
                        // Endpoint closed
                        break;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Received SIGINT, initiating graceful shutdown...");

                // Stop accepting new connections
                endpoint.close(0u32.into(), b"server shutting down");

                // Signal all tasks to shutdown
                let _ = shutdown_tx.send(());

                break;
            }
        }
    }

    // Wait for cleanup task to finish
    let _ = cleanup_handle.await;

    // Wait for all active connections to finish
    let handles: Vec<_> = {
        let mut conns = active_connections.lock().await;
        std::mem::take(&mut *conns)
    };

    for handle in handles {
        let _ = handle.await;
    }

    tracing::info!("Server shutdown complete");

    Ok(())
}

/// Loads TLS configuration from files or generates a new certificate.
fn load_tls_config(args: &ServerArgs) -> Result<(CertKeyPair, bool, Option<String>)> {
    match (&args.tls_cert, &args.tls_key) {
        (Some(cert_path), Some(key_path)) => {
            // When paths are specified, files must exist
            let cert_key = load_cert_key(cert_path, key_path)
                .map_err(|e| Error::Config(format!("failed to load TLS certificate: {}", e)))?;
            Ok((cert_key, false, None))
        }
        (None, None) => {
            // When not specified, auto-generate in config directory
            let config_dir = args
                .config_dir
                .clone()
                .unwrap_or_else(default_config_dir);
            let (cert_key, generated) = load_or_generate_cert(&config_dir)
                .map_err(|e| Error::Config(format!("failed to load or generate certificate: {}", e)))?;
            Ok((cert_key, generated, Some(config_dir.display().to_string())))
        }
        _ => Err(Error::Config(
            "both --tls-cert and --tls-key must be specified together".to_string(),
        )),
    }
}

/// Parses a listen address string into a SocketAddr.
fn parse_listen_address(listen: &str) -> Result<SocketAddr> {
    // Handle ":port" format by prepending "0.0.0.0"
    let addr_str = if listen.starts_with(':') {
        format!("0.0.0.0{}", listen)
    } else {
        listen.to_string()
    };

    addr_str
        .parse()
        .map_err(|e| Error::Config(format!("invalid listen address '{}': {}", listen, e)))
}

/// Prints the startup message.
fn print_startup_message(
    args: &ServerArgs,
    cert_key: &CertKeyPair,
    auto_generated: bool,
    config_path: Option<&str>,
) {
    eprintln!("Starting server...");
    eprintln!("  Listen: {}", args.listen);
    eprintln!("  Backend: {}", args.backend);
    eprintln!("  ALPN: {}", args.alpn);
    eprintln!("  Idle Timeout: {}", format_duration(args.idle_timeout));
    eprintln!("  Keep Alive: {}", format_duration(args.keep_alive));
    eprintln!("  Max Buffer Bytes: {}", args.max_buffer_bytes);
    eprintln!("  Resume Max Age: {}", format_duration(args.resume_max_age));
    eprintln!("  Fingerprint (SHA-256): {}", cert_key.fingerprint);

    if auto_generated {
        if let Some(path) = config_path {
            eprintln!("Certificate auto-generated and saved to {}", path);
        }
    }
}

/// Handles a single QUIC connection.
///
/// The client-driven protocol flow:
/// 1. Client opens bidirectional stream and sends CONNECT_REQ or RESUME_REQ
/// 2. Server accepts the stream and reads the first frame
/// 3. If CONNECT_REQ: create new session, send SESSION_INIT, start relay
/// 4. If RESUME_REQ: restore existing session, send RESUME_OK, resume relay
/// 5. Otherwise: send CLOSE with error and return
async fn handle_connection(
    connection: quinn::Connection,
    backend: &str,
    max_buffer_bytes: u64,
    session_manager: Arc<Mutex<SessionManager>>,
    shutdown_rx: Option<broadcast::Receiver<()>>,
) -> Result<()> {
    // Client opens the bidirectional stream and sends the first frame
    // Server accepts the stream (this blocks until client sends data)
    let (send_stream, mut recv_stream) = connection
        .accept_bi()
        .await
        .map_err(|e| Error::QuicConnectionFailed(format!("failed to accept stream: {}", e)))?;

    let mut send_stream = send_stream;

    // Wait for the first frame from client (no timeout - relies on QUIC idle_timeout)
    let mut buffer = BytesMut::with_capacity(READ_BUFFER_SIZE);
    let first_frame = match read_first_frame(&mut recv_stream, &mut buffer).await {
        Ok(Some(frame)) => frame,
        Ok(None) => {
            // Stream closed before receiving any frame
            tracing::debug!("stream closed before receiving first frame");
            return Err(Error::QuicConnectionFailed(
                "stream closed before receiving first frame".to_string(),
            ));
        }
        Err(e) => {
            return Err(e);
        }
    };

    // Dispatch based on the first frame type
    match first_frame {
        Frame::ConnectReq => {
            handle_new_connection(
                send_stream,
                recv_stream,
                buffer,
                backend,
                max_buffer_bytes,
                session_manager,
                shutdown_rx,
            )
            .await
        }
        Frame::ResumeReq {
            session_id: req_session_id,
            last_offset,
            token: req_token,
        } => {
            handle_resume_connection(
                send_stream,
                recv_stream,
                buffer,
                req_session_id,
                last_offset,
                req_token,
                backend,
                session_manager,
                shutdown_rx,
            )
            .await
        }
        other => {
            // Unexpected frame type - send CLOSE and return error
            let reason = format!("unexpected first frame: expected CONNECT_REQ or RESUME_REQ, got {:?}",
                frame_type_name(&other));
            tracing::warn!(reason, "protocol error");

            let close_frame = Frame::Close {
                reason: reason.clone(),
            };
            let mut buf = BytesMut::new();
            close_frame.encode(&mut buf);
            let _ = send_stream.write_all(&buf).await;
            let _ = send_stream.finish();

            Err(Error::QuicConnectionFailed(reason))
        }
    }
}

/// Returns a human-readable name for a frame type.
fn frame_type_name(frame: &Frame) -> &'static str {
    match frame {
        Frame::Data { .. } => "DATA",
        Frame::Ack { .. } => "ACK",
        Frame::ResumeReq { .. } => "RESUME_REQ",
        Frame::ResumeOk { .. } => "RESUME_OK",
        Frame::ResumeReject { .. } => "RESUME_REJECT",
        Frame::Close { .. } => "CLOSE",
        Frame::SessionInit { .. } => "SESSION_INIT",
        Frame::ConnectReq => "CONNECT_REQ",
    }
}

/// Handles a new connection initiated by CONNECT_REQ.
async fn handle_new_connection(
    mut send_stream: SendStream,
    recv_stream: RecvStream,
    buffer: BytesMut,
    backend: &str,
    max_buffer_bytes: u64,
    session_manager: Arc<Mutex<SessionManager>>,
    shutdown_rx: Option<broadcast::Receiver<()>>,
) -> Result<()> {
    // Create new session
    let (session_id, token) = {
        let mut manager = session_manager.lock().await;
        manager.create_session(max_buffer_bytes)
    };

    tracing::debug!(session_id = ?session_id, "created new session");

    // Send SESSION_INIT frame to client
    let session_init_frame = Frame::SessionInit {
        session_id,
        token: token.clone(),
    };
    let mut init_buf = BytesMut::new();
    session_init_frame.encode(&mut init_buf);

    if let Err(e) = send_stream.write_all(&init_buf).await {
        tracing::error!(session_id = ?session_id, error = %e, "failed to send SESSION_INIT");
        session_manager.lock().await.remove_session(&session_id);
        return Err(Error::QuicConnectionFailed(format!(
            "failed to send SESSION_INIT: {}",
            e
        )));
    }

    // Connect to backend
    let backend_tcp = match TcpStream::connect(backend).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::error!(backend = %backend, error = %e, "backend connection failed");

            // Send CLOSE frame
            let close_frame = Frame::Close {
                reason: format!("backend connection failed: {}", e),
            };
            let mut buf = BytesMut::new();
            close_frame.encode(&mut buf);

            let _ = send_stream.write_all(&buf).await;
            let _ = send_stream.finish();

            // Cleanup session
            session_manager.lock().await.remove_session(&session_id);

            return Err(Error::QuicConnectionFailed(format!(
                "backend connection failed: {}",
                e
            )));
        }
    };

    // Split backend stream and wrap in Arc<Mutex<>> for sharing
    let (backend_read, backend_write) = backend_tcp.into_split();
    let backend = BackendStream {
        read_half: Arc::new(TokioMutex::new(backend_read)),
        write_half: Arc::new(TokioMutex::new(backend_write)),
    };

    // Store backend stream for potential resume, and set session to active
    {
        let mut manager = session_manager.lock().await;
        manager.store_backend_stream(&session_id, BackendStream {
            read_half: Arc::clone(&backend.read_half),
            write_half: Arc::clone(&backend.write_half),
        });
        if let Some(session) = manager.get_session(&session_id) {
            session.set_state(SessionState::Active);
        }
    }

    // Run relay (no first_frame to pass since CONNECT_REQ has no data)
    let result = run_relay(
        send_stream,
        recv_stream,
        backend,
        &session_id,
        session_manager.clone(),
        None,
        buffer,
        shutdown_rx,
    )
    .await;

    // Set session to disconnected or closed
    {
        let mut manager = session_manager.lock().await;
        if let Some(session) = manager.get_session(&session_id) {
            match &result {
                Ok(_) => session.set_state(SessionState::Closed),
                Err(Error::SessionClosed(_)) => session.set_state(SessionState::Closed),
                Err(Error::QuicDisconnected(_)) => {
                    tracing::info!(session_id = ?session_id, "QUIC disconnected, session can be resumed");
                    session.set_state(SessionState::Disconnected);
                }
                Err(_) => session.set_state(SessionState::Disconnected),
            }
        }
    }

    result
}

/// Reads and parses the first frame from the QUIC stream.
///
/// Returns `Ok(None)` if the stream is closed before receiving any frame.
async fn read_first_frame(
    recv_stream: &mut RecvStream,
    buffer: &mut BytesMut,
) -> Result<Option<Frame>> {
    let mut read_buf = [0u8; READ_BUFFER_SIZE];

    loop {
        // Try to decode a frame from existing buffer data
        if let Some((frame, consumed)) =
            Frame::decode(buffer).map_err(|e| Error::QuicConnectionFailed(e.to_string()))?
        {
            // Remove consumed bytes, keeping any remaining data
            let _ = buffer.split_to(consumed);
            return Ok(Some(frame));
        }

        // Need more data - read from stream
        let n = match recv_stream.read(&mut read_buf).await {
            Ok(n) => n,
            Err(e) => {
                // Connection closed by peer before receiving frame
                tracing::debug!(error = %e, "QUIC stream read ended during frame read");
                return Ok(None);
            }
        };

        match n {
            Some(0) | None => {
                // Stream closed before receiving a complete frame
                return Ok(None);
            }
            Some(n) => {
                buffer.extend_from_slice(&read_buf[..n]);
            }
        }
    }
}

/// Handles a connection that is resuming an existing session.
async fn handle_resume_connection(
    mut send_stream: SendStream,
    recv_stream: RecvStream,
    buffer: BytesMut,
    req_session_id: [u8; SESSION_ID_SIZE],
    last_offset: u64,
    token: Bytes,
    _backend: &str,
    session_manager: Arc<Mutex<SessionManager>>,
    shutdown_rx: Option<broadcast::Receiver<()>>,
) -> Result<()> {
    // Try to resume the session
    let result = {
        let mut manager = session_manager.lock().await;
        manager.try_resume(&req_session_id, &token, last_offset)
    };

    match result {
        Ok((start_offset, ack_offset)) => {
            // Send RESUME_OK with both offsets:
            // - start_offset: for server->client retransmission
            // - ack_offset: highest offset server received from client, for client->server retransmission
            let ok_frame = Frame::ResumeOk { start_offset, ack_offset };
            let mut ok_buf = BytesMut::new();
            ok_frame.encode(&mut ok_buf);

            send_stream
                .write_all(&ok_buf)
                .await
                .map_err(|e| Error::QuicConnectionFailed(format!("failed to send RESUME_OK: {}", e)))?;

            tracing::info!(
                session_id = ?req_session_id,
                start_offset,
                ack_offset,
                "session resumed"
            );

            // Retrieve existing backend stream or error
            let backend = {
                let mut manager = session_manager.lock().await;
                if let Some(session) = manager.get_session(&req_session_id) {
                    session.set_state(SessionState::Active);
                }
                manager.take_backend_stream(&req_session_id)
            };

            let backend = match backend {
                Some(b) => {
                    tracing::info!(session_id = ?req_session_id, "reusing existing backend connection");
                    // Re-store the backend stream for future resumes
                    {
                        let mut manager = session_manager.lock().await;
                        manager.store_backend_stream(&req_session_id, BackendStream {
                            read_half: Arc::clone(&b.read_half),
                            write_half: Arc::clone(&b.write_half),
                        });
                    }
                    b
                }
                None => {
                    // Backend connection was lost, reject resume
                    tracing::warn!(session_id = ?req_session_id, "no backend connection available for resume");

                    let close_frame = Frame::Close {
                        reason: "backend connection lost".to_string(),
                    };
                    let mut buf = BytesMut::new();
                    close_frame.encode(&mut buf);
                    let _ = send_stream.write_all(&buf).await;
                    let _ = send_stream.finish();

                    return Err(Error::QuicConnectionFailed(
                        "backend connection lost during disconnect".to_string(),
                    ));
                }
            };

            // Retransmit buffered server->client data from start_offset
            if start_offset > 0 {
                let data_to_send = {
                    let mut manager = session_manager.lock().await;
                    if let Some(session) = manager.get_session(&req_session_id) {
                        session.send_buffer().get_from(start_offset)
                    } else {
                        Vec::new()
                    }
                };

                for (offset, data) in data_to_send {
                    let data_frame = Frame::Data { offset, data };
                    let mut frame_buf = BytesMut::new();
                    data_frame.encode(&mut frame_buf);
                    send_stream
                        .write_all(&frame_buf)
                        .await
                        .map_err(|e| Error::QuicConnectionFailed(format!("failed to retransmit DATA: {}", e)))?;
                }
                tracing::debug!(session_id = ?req_session_id, start_offset, "retransmitted buffered data");
            }

            // Run relay for resumed session
            let relay_result = run_relay(
                send_stream,
                recv_stream,
                backend,
                &req_session_id,
                session_manager.clone(),
                None,
                buffer,
                shutdown_rx,
            )
            .await;

            // Set session state based on result
            {
                let mut manager = session_manager.lock().await;
                if let Some(session) = manager.get_session(&req_session_id) {
                    match &relay_result {
                        Ok(_) => session.set_state(SessionState::Closed),
                        Err(Error::SessionClosed(_)) => session.set_state(SessionState::Closed),
                        Err(Error::QuicDisconnected(_)) => {
                            tracing::info!(session_id = ?req_session_id, "QUIC disconnected, session can be resumed");
                            session.set_state(SessionState::Disconnected);
                        }
                        Err(_) => session.set_state(SessionState::Disconnected),
                    }
                }
            }

            relay_result
        }
        Err(reason) => {
            // Send RESUME_REJECT
            let reject_frame = Frame::ResumeReject { reason: reason.clone() };
            let mut reject_buf = BytesMut::new();
            reject_frame.encode(&mut reject_buf);

            send_stream
                .write_all(&reject_buf)
                .await
                .map_err(|e| {
                    Error::QuicConnectionFailed(format!("failed to send RESUME_REJECT: {}", e))
                })?;

            tracing::warn!(
                session_id = ?req_session_id,
                reason,
                "session resume rejected"
            );

            Err(Error::QuicConnectionFailed(format!(
                "session resume rejected: {}",
                reason
            )))
        }
    }
}

/// Runs the bidirectional relay between QUIC and TCP streams.
async fn run_relay(
    send_stream: SendStream,
    recv_stream: RecvStream,
    backend: BackendStream,
    session_id: &[u8; SESSION_ID_SIZE],
    session_manager: Arc<Mutex<SessionManager>>,
    first_frame: Option<Frame>,
    initial_buffer: BytesMut,
    mut shutdown_rx: Option<broadcast::Receiver<()>>,
) -> Result<()> {
    let backend_read = backend.read_half;
    let backend_write = backend.write_half;
    let send_stream = Arc::new(Mutex::new(send_stream));

    // Spawn task for QUIC -> Backend (receiving from client)
    let quic_to_backend = {
        let session_manager = Arc::clone(&session_manager);
        let send_stream = Arc::clone(&send_stream);
        let session_id = *session_id;

        tokio::spawn(async move {
            relay_quic_to_backend(
                recv_stream,
                backend_write,
                &session_id,
                session_manager,
                send_stream,
                first_frame,
                initial_buffer,
            )
            .await
        })
    };

    // Spawn task for Backend -> QUIC (sending to client)
    let backend_to_quic = {
        let session_manager = Arc::clone(&session_manager);
        let send_stream = Arc::clone(&send_stream);
        let session_id = *session_id;

        tokio::spawn(async move {
            relay_backend_to_quic(backend_read, &session_id, session_manager, send_stream).await
        })
    };

    // Get abort handles to properly cancel tasks
    // Note: Dropping a JoinHandle does NOT cancel the task - we must abort explicitly
    let quic_abort = quic_to_backend.abort_handle();
    let backend_abort = backend_to_quic.abort_handle();

    // Wait for either task to complete, shutdown signal, then abort the other
    let result = tokio::select! {
        quic_result = quic_to_backend => {
            backend_abort.abort();
            quic_result.map_err(|e| Error::QuicConnectionFailed(format!("relay task panicked: {}", e)))?
        }
        backend_result = backend_to_quic => {
            quic_abort.abort();
            backend_result.map_err(|e| Error::QuicConnectionFailed(format!("relay task panicked: {}", e)))?
        }
        _ = async {
            if let Some(ref mut rx) = shutdown_rx {
                let _ = rx.recv().await;
            } else {
                // No shutdown receiver, wait forever
                std::future::pending::<()>().await;
            }
        } => {
            // Shutdown signal received - send CLOSE on existing stream
            tracing::info!(session_id = ?session_id, "shutdown signal received, sending CLOSE frame");
            quic_abort.abort();
            backend_abort.abort();

            let close_frame = Frame::Close {
                reason: "server shutting down".to_string(),
            };
            let mut close_buf = BytesMut::new();
            close_frame.encode(&mut close_buf);

            let mut stream = send_stream.lock().await;
            let _ = stream.write_all(&close_buf).await;
            let _ = stream.finish();

            Err(Error::SessionClosed("server shutting down".to_string()))
        }
    };

    result
}

/// Relays data from QUIC to backend TCP.
async fn relay_quic_to_backend(
    mut recv_stream: RecvStream,
    backend_write: Arc<TokioMutex<tokio::net::tcp::OwnedWriteHalf>>,
    session_id: &[u8; SESSION_ID_SIZE],
    session_manager: Arc<Mutex<SessionManager>>,
    send_stream: Arc<Mutex<SendStream>>,
    first_frame: Option<Frame>,
    mut buffer: BytesMut,
) -> Result<()> {
    // Process the first frame if it was already read during connection setup
    if let Some(frame) = first_frame {
        process_frame(
            frame,
            session_id,
            &session_manager,
            &send_stream,
            &backend_write,
        )
        .await?;
    }

    // Process any remaining frames in the initial buffer
    while let Some((frame, consumed)) =
        Frame::decode(&buffer).map_err(|e| Error::QuicConnectionFailed(e.to_string()))?
    {
        let _ = buffer.split_to(consumed);
        process_frame(
            frame,
            session_id,
            &session_manager,
            &send_stream,
            &backend_write,
        )
        .await?;
    }

    loop {
        // Read from QUIC stream
        let mut read_buf = [0u8; READ_BUFFER_SIZE];
        let n = match recv_stream.read(&mut read_buf).await {
            Ok(n) => n,
            Err(e) => {
                // QUIC connection error - this is a temporary disconnection, session can be resumed
                tracing::debug!(session_id = ?session_id, error = %e, "QUIC stream read error");
                return Err(Error::QuicDisconnected(e.to_string()));
            }
        };

        match n {
            Some(0) | None => {
                // Stream closed
                tracing::debug!(session_id = ?session_id, "QUIC stream closed");
                break;
            }
            Some(n) => {
                buffer.extend_from_slice(&read_buf[..n]);

                // Process complete frames
                while let Some((frame, consumed)) =
                    Frame::decode(&buffer).map_err(|e| Error::QuicConnectionFailed(e.to_string()))?
                {
                    let _ = buffer.split_to(consumed);
                    process_frame(
                        frame,
                        session_id,
                        &session_manager,
                        &send_stream,
                        &backend_write,
                    )
                    .await?;
                }
            }
        }
    }

    Ok(())
}

/// Processes a single frame from the QUIC stream.
async fn process_frame(
    frame: Frame,
    session_id: &[u8; SESSION_ID_SIZE],
    session_manager: &Arc<Mutex<SessionManager>>,
    send_stream: &Arc<Mutex<SendStream>>,
    backend_write: &Arc<TokioMutex<tokio::net::tcp::OwnedWriteHalf>>,
) -> Result<()> {
    match frame {
        Frame::Data { offset, data } => {
            // Insert into receive buffer and collect data to send to backend
            let (ack_offset, data_to_write) = {
                let mut manager = session_manager.lock().await;
                if let Some(session) = manager.get_session(session_id) {
                    session
                        .recv_buffer_mut()
                        .insert(offset, data.clone())
                        .map_err(|_| Error::BufferLimitExceeded)?;

                    // Read contiguous data
                    let mut data_to_write = Vec::new();
                    while let Some((data, _)) = session.recv_buffer_mut().read() {
                        data_to_write.push(data);
                    }

                    (session.recv_buffer().acked_offset(), data_to_write)
                } else {
                    return Ok(());
                }
            };

            // Write data to backend (outside of session_manager lock)
            if !data_to_write.is_empty() {
                let mut writer = backend_write.lock().await;
                for data in data_to_write {
                    writer.write_all(&data).await.map_err(Error::Io)?;
                }
            }

            // Send ACK
            let ack_frame = Frame::Ack { offset: ack_offset };
            let mut ack_buf = BytesMut::new();
            ack_frame.encode(&mut ack_buf);

            send_stream
                .lock()
                .await
                .write_all(&ack_buf)
                .await
                .map_err(|e| {
                    Error::QuicConnectionFailed(format!("failed to send ACK: {}", e))
                })?;
        }
        Frame::Ack { offset } => {
            // Process ACK - release data from send buffer
            let mut manager = session_manager.lock().await;
            if let Some(session) = manager.get_session(session_id) {
                session.send_buffer_mut().ack(offset);
            }
        }
        Frame::ResumeReq { .. } => {
            // RESUME_REQ should only be received at connection start
            // If we receive it here, it's a protocol error
            tracing::warn!(
                session_id = ?session_id,
                "unexpected RESUME_REQ frame after connection established"
            );
        }
        Frame::Close { reason } => {
            tracing::info!(session_id = ?session_id, reason, "received CLOSE frame from client");
            return Err(Error::SessionClosed(reason));
        }
        _ => {
            tracing::warn!(session_id = ?session_id, "unexpected frame type");
        }
    }

    Ok(())
}

/// Relays data from backend TCP to QUIC.
async fn relay_backend_to_quic(
    backend_read: Arc<TokioMutex<tokio::net::tcp::OwnedReadHalf>>,
    session_id: &[u8; SESSION_ID_SIZE],
    session_manager: Arc<Mutex<SessionManager>>,
    send_stream: Arc<Mutex<SendStream>>,
) -> Result<()> {
    let mut read_buf = [0u8; READ_BUFFER_SIZE];

    loop {
        let n = {
            let mut reader = backend_read.lock().await;
            match reader.read(&mut read_buf).await {
                Ok(n) => n,
                Err(e) => {
                    // Send CLOSE frame on backend read error
                    let close_frame = Frame::Close {
                        reason: format!("backend error: {}", e),
                    };
                    let mut close_buf = BytesMut::new();
                    close_frame.encode(&mut close_buf);

                    let mut stream = send_stream.lock().await;
                    let _ = stream.write_all(&close_buf).await;
                    let _ = stream.finish();
                    drop(stream);

                    // Wait for CLOSE frame to be transmitted before connection is dropped
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

                    return Err(Error::SessionClosed(format!("backend error: {}", e)));
                }
            }
        };

        if n == 0 {
            // Backend closed
            tracing::debug!(session_id = ?session_id, "backend connection closed");

            // Send CLOSE frame and finish the stream
            let close_frame = Frame::Close {
                reason: "backend closed".to_string(),
            };
            let mut close_buf = BytesMut::new();
            close_frame.encode(&mut close_buf);

            let mut stream = send_stream.lock().await;
            let _ = stream.write_all(&close_buf).await;
            let _ = stream.finish();
            drop(stream);

            // Wait for CLOSE frame to be transmitted before connection is dropped
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;

            return Err(Error::SessionClosed("backend closed".to_string()));
        }

        let data = Bytes::copy_from_slice(&read_buf[..n]);

        // Push to send buffer and get offset
        let offset = {
            let mut manager = session_manager.lock().await;
            if let Some(session) = manager.get_session(session_id) {
                session
                    .send_buffer_mut()
                    .push(data.clone())
                    .map_err(|_| Error::BufferLimitExceeded)?
            } else {
                return Err(Error::QuicConnectionFailed("session not found".to_string()));
            }
        };

        // Send DATA frame
        let data_frame = Frame::Data { offset, data };
        let mut data_buf = BytesMut::new();
        data_frame.encode(&mut data_buf);

        send_stream
            .lock()
            .await
            .write_all(&data_buf)
            .await
            .map_err(|e| Error::QuicConnectionFailed(format!("failed to send DATA: {}", e)))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: format_duration tests are now in common.rs to avoid duplication.

    #[test]
    fn test_parse_listen_address_with_port_only() {
        let addr = parse_listen_address(":9443").unwrap();
        assert_eq!(addr.port(), 9443);
        assert_eq!(addr.ip(), std::net::Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_parse_listen_address_with_full_addr() {
        let addr = parse_listen_address("127.0.0.1:9443").unwrap();
        assert_eq!(addr.port(), 9443);
        assert_eq!(addr.ip(), std::net::Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn test_parse_listen_address_invalid() {
        let result = parse_listen_address("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_listen_address_ipv6() {
        let addr = parse_listen_address("[::1]:9443").unwrap();
        assert_eq!(addr.port(), 9443);
    }
}
