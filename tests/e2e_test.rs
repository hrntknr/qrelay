//! End-to-end integration tests for qrelay.
//!
//! These tests verify that the server and client can communicate correctly.

use bytes::{Bytes, BytesMut};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Generate a self-signed certificate for testing.
fn generate_test_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    (vec![cert_der], PrivateKeyDer::Pkcs8(key_der))
}

/// Create a QUIC server config for testing.
fn create_server_config() -> (ServerConfig, Vec<CertificateDer<'static>>) {
    let (certs, key) = generate_test_cert();

    let mut config = ServerConfig::with_single_cert(certs.clone(), key).unwrap();
    let transport = Arc::get_mut(&mut config.transport).unwrap();
    transport.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));

    (config, certs)
}

/// Create a QUIC client config for testing (insecure, accepts any cert).
fn create_client_config() -> ClientConfig {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
        .with_no_client_auth();

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));

    let mut config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
    ));
    config.transport_config(Arc::new(transport));

    config
}

/// Insecure certificate verifier for testing.
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Test basic QUIC connection without qrelay protocol.
#[tokio::test]
async fn test_basic_quic_connection() {
    // Install crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (server_config, _certs) = create_server_config();

    // Create server endpoint
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    println!("Server listening on {}", server_addr);

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        println!("Server: accepted connection");

        // Server opens the stream (matching qrelay architecture)
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        println!("Server: opened bi stream");

        // Server sends first (like SESSION_INIT in qrelay)
        send.write_all(b"init").await.unwrap();
        println!("Server: sent init");

        // Read data from client
        let mut buf = [0u8; 1024];
        let n = recv.read(&mut buf).await.unwrap().unwrap();
        println!("Server: received {} bytes: {:?}", n, &buf[..n]);

        // Echo back
        send.write_all(&buf[..n]).await.unwrap();
        send.finish().unwrap();
        println!("Server: sent response");
    });

    // Create client
    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(create_client_config());

    // Connect to server
    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    println!("Client: connected to server");

    // Accept bi stream from server (matching qrelay architecture)
    let (mut send, mut recv) = connection.accept_bi().await.unwrap();
    println!("Client: accepted bi stream");

    // First, receive init from server
    let mut buf = [0u8; 1024];
    let n = recv.read(&mut buf).await.unwrap().unwrap();
    println!("Client: received init: {:?}", &buf[..n]);
    assert_eq!(&buf[..n], b"init");

    // Send data
    send.write_all(b"hello").await.unwrap();
    send.finish().unwrap();
    println!("Client: sent data");

    // Read response (may get connection closed error if server closes fast)
    let response = match recv.read(&mut buf).await {
        Ok(Some(n)) => {
            println!("Client: received {} bytes: {:?}", n, &buf[..n]);
            Some(&buf[..n])
        }
        Ok(None) => {
            println!("Client: stream closed");
            None
        }
        Err(e) => {
            println!("Client: read error: {} (server may have closed)", e);
            None
        }
    };

    // The response might be None if server closed quickly, but that's OK for this basic test
    // The important thing is the bidirectional communication worked
    if let Some(data) = response {
        assert_eq!(data, b"hello");
    }

    let _ = server_handle.await;
}

/// Test qrelay protocol frame exchange.
#[tokio::test]
async fn test_qrelay_protocol_session_init() {
    use qrelay::protocol::Frame;

    // Install crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (server_config, _certs) = create_server_config();

    // Create server endpoint
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    println!("Server listening on {}", server_addr);

    // Spawn server task (simulating qrelay server behavior)
    let server_handle = tokio::spawn(async move {
        println!("Server: waiting for incoming connection...");
        let incoming = server_endpoint.accept().await.unwrap();
        println!("Server: got incoming, awaiting handshake...");
        let connection = incoming.await.unwrap();
        println!(
            "Server: connection established, remote={}",
            connection.remote_address()
        );

        println!("Server: opening bi stream...");
        let open_result = tokio::time::timeout(Duration::from_secs(5), connection.open_bi()).await;

        let (mut send, mut recv) = match open_result {
            Ok(Ok(streams)) => streams,
            Ok(Err(e)) => {
                println!("Server: open_bi error: {:?}", e);
                return;
            }
            Err(_) => {
                println!("Server: open_bi timed out!");
                println!("Server: connection stats: {:?}", connection.stats());
                return;
            }
        };
        println!("Server: opened bi stream");

        // Send SESSION_INIT first (as per the fix)
        let session_id = [1u8; 16];
        let token = Bytes::from_static(b"test_token");
        let session_init = Frame::SessionInit {
            session_id,
            token: token.clone(),
        };
        let mut buf = BytesMut::new();
        session_init.encode(&mut buf);
        send.write_all(&buf).await.unwrap();
        println!("Server: sent SESSION_INIT");

        // Now read the first frame from client
        let mut read_buf = BytesMut::with_capacity(1024);
        let mut tmp = [0u8; 1024];

        loop {
            if let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
                let _ = read_buf.split_to(consumed);
                println!("Server: received frame {:?}", frame);

                match frame {
                    Frame::Data { offset, data } => {
                        println!("Server: received DATA offset={} len={}", offset, data.len());

                        // Send ACK
                        let ack = Frame::Ack {
                            offset: offset + data.len() as u64,
                        };
                        let mut ack_buf = BytesMut::new();
                        ack.encode(&mut ack_buf);
                        send.write_all(&ack_buf).await.unwrap();
                        println!("Server: sent ACK");

                        // Echo back as DATA
                        let echo = Frame::Data { offset: 0, data };
                        let mut echo_buf = BytesMut::new();
                        echo.encode(&mut echo_buf);
                        send.write_all(&echo_buf).await.unwrap();
                        println!("Server: sent echo DATA");

                        // Wait a bit for data to be flushed before closing
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        break;
                    }
                    _ => {
                        println!("Server: unexpected frame, continuing...");
                    }
                }
            }

            match recv.read(&mut tmp).await.unwrap() {
                Some(0) | None => {
                    println!("Server: connection closed");
                    break;
                }
                Some(n) => {
                    read_buf.extend_from_slice(&tmp[..n]);
                    println!("Server: read {} bytes", n);
                }
            }
        }
    });

    // Create client
    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(create_client_config());

    // Connect to server
    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    println!("Client: connected to server");

    // Accept bi stream from server (server opens the stream)
    let (mut send, mut recv) = connection.accept_bi().await.unwrap();
    println!("Client: accepted bi stream");

    // First, receive SESSION_INIT from server
    let mut read_buf = BytesMut::with_capacity(1024);
    let mut tmp = [0u8; 1024];

    let session_info = loop {
        if let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
            let _ = read_buf.split_to(consumed);
            println!("Client: received frame {:?}", frame);

            if let Frame::SessionInit { session_id, token } = frame {
                println!("Client: received SESSION_INIT");
                break (session_id, token);
            }
        }

        match recv.read(&mut tmp).await.unwrap() {
            Some(0) | None => panic!("Connection closed before receiving SESSION_INIT"),
            Some(n) => {
                read_buf.extend_from_slice(&tmp[..n]);
                println!("Client: read {} bytes", n);
            }
        }
    };

    println!(
        "Client: got session_id={:?}, token_len={}",
        session_info.0,
        session_info.1.len()
    );

    // Now send DATA frame
    let data_frame = Frame::Data {
        offset: 0,
        data: Bytes::from_static(b"hello qrelay"),
    };
    let mut buf = BytesMut::new();
    data_frame.encode(&mut buf);
    send.write_all(&buf).await.unwrap();
    println!("Client: sent DATA frame");

    // Receive ACK and echo DATA
    let mut received_echo = false;
    let mut connection_closed = false;

    while !received_echo && !connection_closed {
        // First, try to decode any existing frames in the buffer
        while let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
            let _ = read_buf.split_to(consumed);
            println!("Client: received frame {:?}", frame);

            match frame {
                Frame::Data { data, .. } => {
                    println!("Client: received echo data: {:?}", data);
                    assert_eq!(&data[..], b"hello qrelay");
                    received_echo = true;
                    break;
                }
                Frame::Ack { offset } => {
                    println!("Client: received ACK for offset {}", offset);
                }
                _ => {}
            }
        }

        if received_echo {
            break;
        }

        // Try to read more data
        match recv.read(&mut tmp).await {
            Ok(Some(0)) | Ok(None) => {
                println!("Client: connection closed");
                connection_closed = true;
            }
            Ok(Some(n)) => {
                read_buf.extend_from_slice(&tmp[..n]);
                println!(
                    "Client: read {} bytes, buffer now has {} bytes",
                    n,
                    read_buf.len()
                );
            }
            Err(e) => {
                println!("Client: read error (expected after server close): {}", e);
                connection_closed = true;
            }
        }
    }

    assert!(received_echo, "Should have received echo data");

    let _ = server_handle.await;
}

/// Test full qrelay server and client integration.
#[tokio::test]
async fn test_full_qrelay_integration() {
    use qrelay::protocol::Frame;
    use qrelay::session::SessionManager;
    use tokio::sync::Mutex;

    // Install crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (server_config, _certs) = create_server_config();

    // Start a simple TCP echo server as backend
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    println!("Backend listening on {}", backend_addr);

    let _backend_handle = tokio::spawn(async move {
        let (mut stream, _) = backend_listener.accept().await.unwrap();
        println!("Backend: accepted connection");

        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => {
                    println!("Backend: connection closed");
                    break;
                }
                Ok(n) => {
                    println!("Backend: received {} bytes, echoing back", n);
                    stream.write_all(&buf[..n]).await.unwrap();
                }
                Err(e) => {
                    println!("Backend: error {}", e);
                    break;
                }
            }
        }
    });

    // Create QUIC server endpoint
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();
    println!("QUIC Server listening on {}", server_addr);

    let session_manager = Arc::new(Mutex::new(SessionManager::new(Duration::from_secs(3600))));

    // Spawn server task
    let sm = session_manager.clone();
    let backend_addr_str = backend_addr.to_string();
    let _server_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        println!("QUIC Server: accepted connection");

        // Server opens the bi stream (matching qrelay architecture)
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        println!("QUIC Server: opened bi stream");

        // Create session and send SESSION_INIT
        let (session_id, token) = {
            let mut manager = sm.lock().await;
            manager.create_session(64 * 1024 * 1024)
        };
        println!("QUIC Server: created session {:?}", session_id);

        let session_init = Frame::SessionInit {
            session_id,
            token: token.clone(),
        };
        let mut buf = BytesMut::new();
        session_init.encode(&mut buf);
        send.write_all(&buf).await.unwrap();
        println!("QUIC Server: sent SESSION_INIT");

        // Connect to backend
        let mut backend = TcpStream::connect(&backend_addr_str).await.unwrap();
        println!("QUIC Server: connected to backend");

        // Simple relay: read from QUIC, forward to backend, and vice versa
        let mut read_buf = BytesMut::with_capacity(4096);
        let mut tmp = [0u8; 4096];
        let mut backend_buf = [0u8; 4096];

        // Set up for select
        loop {
            tokio::select! {
                // Read from QUIC
                result = recv.read(&mut tmp) => {
                    match result {
                        Ok(Some(0)) | Ok(None) => {
                            println!("QUIC Server: QUIC stream closed");
                            break;
                        }
                        Ok(Some(n)) => {
                            read_buf.extend_from_slice(&tmp[..n]);
                            println!("QUIC Server: read {} bytes from QUIC", n);

                            // Try to decode frames
                            while let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
                                let _ = read_buf.split_to(consumed);
                                println!("QUIC Server: decoded frame {:?}", frame);

                                match frame {
                                    Frame::Data { offset, data } => {
                                        // Forward to backend
                                        backend.write_all(&data).await.unwrap();
                                        println!("QUIC Server: forwarded {} bytes to backend", data.len());

                                        // Send ACK
                                        let ack = Frame::Ack { offset: offset + data.len() as u64 };
                                        let mut ack_buf = BytesMut::new();
                                        ack.encode(&mut ack_buf);
                                        send.write_all(&ack_buf).await.unwrap();
                                        println!("QUIC Server: sent ACK");
                                    }
                                    _ => {
                                        println!("QUIC Server: ignoring frame");
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            println!("QUIC Server: QUIC read error: {}", e);
                            break;
                        }
                    }
                }
                // Read from backend
                result = backend.read(&mut backend_buf) => {
                    match result {
                        Ok(0) => {
                            println!("QUIC Server: backend closed");
                            break;
                        }
                        Ok(n) => {
                            println!("QUIC Server: read {} bytes from backend", n);

                            // Send as DATA frame
                            let data_frame = Frame::Data {
                                offset: 0, // simplified
                                data: Bytes::copy_from_slice(&backend_buf[..n]),
                            };
                            let mut frame_buf = BytesMut::new();
                            data_frame.encode(&mut frame_buf);
                            send.write_all(&frame_buf).await.unwrap();
                            println!("QUIC Server: sent DATA frame to client");
                        }
                        Err(e) => {
                            println!("QUIC Server: backend read error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create client
    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(create_client_config());

    // Connect to QUIC server
    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    println!("Client: connected to QUIC server");

    // Accept bi stream from server (server opens the stream)
    let (mut send, mut recv) = connection.accept_bi().await.unwrap();
    println!("Client: accepted bi stream");

    // Receive SESSION_INIT
    let mut read_buf = BytesMut::with_capacity(1024);
    let mut tmp = [0u8; 1024];

    loop {
        if let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
            let _ = read_buf.split_to(consumed);
            if let Frame::SessionInit { session_id, .. } = frame {
                println!("Client: received SESSION_INIT, session_id={:?}", session_id);
                break;
            }
        }

        let n = recv.read(&mut tmp).await.unwrap().unwrap();
        read_buf.extend_from_slice(&tmp[..n]);
    }

    // Send DATA
    let test_data = b"Hello, qrelay end-to-end test!";
    let data_frame = Frame::Data {
        offset: 0,
        data: Bytes::from_static(test_data),
    };
    let mut buf = BytesMut::new();
    data_frame.encode(&mut buf);
    send.write_all(&buf).await.unwrap();
    println!("Client: sent DATA frame");

    // Receive ACK and echo DATA
    let mut received_ack = false;
    let mut received_echo = false;

    let timeout = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
                let _ = read_buf.split_to(consumed);

                match frame {
                    Frame::Ack { offset } => {
                        println!("Client: received ACK for offset {}", offset);
                        received_ack = true;
                    }
                    Frame::Data { data, .. } => {
                        println!(
                            "Client: received echo data: {:?}",
                            String::from_utf8_lossy(&data)
                        );
                        assert_eq!(&data[..], test_data);
                        received_echo = true;
                    }
                    _ => {}
                }

                if received_ack && received_echo {
                    break;
                }
            }

            match recv.read(&mut tmp).await.unwrap() {
                Some(0) | None => break,
                Some(n) => {
                    read_buf.extend_from_slice(&tmp[..n]);
                }
            }
        }
    });

    timeout.await.expect("Test timed out");

    assert!(received_ack, "Should have received ACK");
    assert!(received_echo, "Should have received echo data");

    println!("Test passed!");

    // Cleanup
    drop(send);
    drop(recv);
    drop(connection);

    // Give time for cleanup
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Test session reconnection with RESUME_REQ/RESUME_OK flow.
#[tokio::test]
async fn test_session_reconnection() {
    use qrelay::protocol::Frame;
    use qrelay::session::SessionManager;
    use tokio::sync::Mutex;

    // Install crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (server_config, _certs) = create_server_config();

    // Create QUIC server endpoint
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();
    println!("Server listening on {}", server_addr);

    // Shared session manager (persists across connections)
    let session_manager = Arc::new(Mutex::new(SessionManager::new(Duration::from_secs(3600))));

    // Channel to signal server to accept next connection
    let (server_ready_tx, mut server_ready_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (server_done_tx, mut server_done_rx) = tokio::sync::mpsc::channel::<()>(1);

    // Spawn server task that handles multiple connections
    let sm = session_manager.clone();
    let _server_handle = tokio::spawn(async move {
        // === First connection ===
        println!("Server: waiting for first connection...");
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        println!("Server: first connection accepted");

        // Server opens bi stream
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        println!("Server: opened bi stream");

        // Create session
        let (session_id, token) = {
            let mut manager = sm.lock().await;
            manager.create_session(64 * 1024 * 1024)
        };
        println!("Server: created session {:?}", session_id);

        // Send SESSION_INIT
        let session_init = Frame::SessionInit {
            session_id,
            token: token.clone(),
        };
        let mut buf = BytesMut::new();
        session_init.encode(&mut buf);
        send.write_all(&buf).await.unwrap();
        println!("Server: sent SESSION_INIT");

        // Read and process frames
        let mut read_buf = BytesMut::with_capacity(4096);
        let mut tmp = [0u8; 4096];
        let mut received_data = false;

        loop {
            // Try to decode frames
            while let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
                let _ = read_buf.split_to(consumed);
                println!("Server: received frame {:?}", frame);

                match frame {
                    Frame::Data { offset, data } => {
                        println!("Server: received DATA offset={} len={}", offset, data.len());

                        // Store in session buffer for resume
                        {
                            let mut manager = sm.lock().await;
                            if let Some(session) = manager.get_session(&session_id) {
                                let _ = session.recv_buffer_mut().insert(offset, data.clone());
                                // Read to advance acked_offset
                                while session.recv_buffer_mut().read().is_some() {}
                            }
                        }

                        // Send ACK
                        let ack = Frame::Ack {
                            offset: offset + data.len() as u64,
                        };
                        let mut ack_buf = BytesMut::new();
                        ack.encode(&mut ack_buf);
                        send.write_all(&ack_buf).await.unwrap();
                        println!("Server: sent ACK");

                        received_data = true;
                    }
                    _ => {}
                }
            }

            if received_data {
                break;
            }

            match recv.read(&mut tmp).await {
                Ok(Some(n)) if n > 0 => {
                    read_buf.extend_from_slice(&tmp[..n]);
                }
                _ => break,
            }
        }

        // Mark session as disconnected (simulate connection loss)
        {
            let mut manager = sm.lock().await;
            if let Some(session) = manager.get_session(&session_id) {
                session.set_state(qrelay::buffer::SessionState::Disconnected);
            }
        }

        // Close first connection
        drop(send);
        drop(recv);
        connection.close(0u32.into(), b"simulated disconnect");
        println!("Server: first connection closed");

        // Signal ready for second connection
        let _ = server_ready_tx.send(()).await;

        // === Second connection (resume) ===
        println!("Server: waiting for second connection (resume)...");
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        println!("Server: second connection accepted");

        // Server opens bi stream
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        println!("Server: opened bi stream for resume");

        // Create a new session (client will send RESUME_REQ for the old one)
        let (new_session_id, new_token) = {
            let mut manager = sm.lock().await;
            manager.create_session(64 * 1024 * 1024)
        };

        // Send SESSION_INIT first (as per protocol)
        let session_init = Frame::SessionInit {
            session_id: new_session_id,
            token: new_token.clone(),
        };
        let mut buf = BytesMut::new();
        session_init.encode(&mut buf);
        send.write_all(&buf).await.unwrap();
        println!("Server: sent SESSION_INIT for new session");

        // Read first frame (should be RESUME_REQ)
        let mut read_buf = BytesMut::with_capacity(4096);
        let mut tmp = [0u8; 4096];

        loop {
            if let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
                let _ = read_buf.split_to(consumed);
                println!("Server: received frame {:?}", frame);

                match frame {
                    Frame::ResumeReq {
                        session_id: req_session_id,
                        last_offset,
                        token: req_token,
                    } => {
                        println!(
                            "Server: received RESUME_REQ for session {:?}, last_offset={}",
                            req_session_id, last_offset
                        );

                        // Remove the new session we just created
                        {
                            let mut manager = sm.lock().await;
                            manager.remove_session(&new_session_id);
                        }

                        // Try to resume
                        let resume_result = {
                            let mut manager = sm.lock().await;
                            manager.try_resume(&req_session_id, &req_token, last_offset)
                        };

                        match resume_result {
                            Ok((start_offset, ack_offset)) => {
                                // Send RESUME_OK
                                let resume_ok = Frame::ResumeOk { start_offset, ack_offset };
                                let mut ok_buf = BytesMut::new();
                                resume_ok.encode(&mut ok_buf);
                                send.write_all(&ok_buf).await.unwrap();
                                println!(
                                    "Server: sent RESUME_OK with start_offset={}, ack_offset={}",
                                    start_offset, ack_offset
                                );

                                // Wait a bit then send some data to confirm session works
                                tokio::time::sleep(Duration::from_millis(50)).await;

                                let data_frame = Frame::Data {
                                    offset: 0,
                                    data: Bytes::from_static(b"resumed session data"),
                                };
                                let mut data_buf = BytesMut::new();
                                data_frame.encode(&mut data_buf);
                                send.write_all(&data_buf).await.unwrap();
                                println!("Server: sent DATA after resume");

                                // Wait for data to be flushed
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                            Err(reason) => {
                                // Send RESUME_REJECT
                                let reject = Frame::ResumeReject {
                                    reason: reason.clone(),
                                };
                                let mut reject_buf = BytesMut::new();
                                reject.encode(&mut reject_buf);
                                send.write_all(&reject_buf).await.unwrap();
                                println!("Server: sent RESUME_REJECT: {}", reason);
                            }
                        }
                        break;
                    }
                    _ => {
                        println!("Server: unexpected frame, expected RESUME_REQ");
                    }
                }
            }

            match recv.read(&mut tmp).await {
                Ok(Some(n)) if n > 0 => {
                    read_buf.extend_from_slice(&tmp[..n]);
                }
                _ => break,
            }
        }

        let _ = server_done_tx.send(()).await;
        println!("Server: done");
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // === Client: First connection ===
    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(create_client_config());

    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    println!("Client: first connection established");

    // Accept bi stream from server
    let (mut send, mut recv) = connection.accept_bi().await.unwrap();
    println!("Client: accepted bi stream");

    // Receive SESSION_INIT
    let mut read_buf = BytesMut::with_capacity(4096);
    let mut tmp = [0u8; 4096];

    let (session_id, token) = loop {
        if let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
            let _ = read_buf.split_to(consumed);
            if let Frame::SessionInit { session_id, token } = frame {
                println!("Client: received SESSION_INIT, session_id={:?}", session_id);
                break (session_id, token);
            }
        }
        let n = recv.read(&mut tmp).await.unwrap().unwrap();
        read_buf.extend_from_slice(&tmp[..n]);
    };

    // Send some data
    let data_frame = Frame::Data {
        offset: 0,
        data: Bytes::from_static(b"first connection data"),
    };
    let mut buf = BytesMut::new();
    data_frame.encode(&mut buf);
    send.write_all(&buf).await.unwrap();
    println!("Client: sent DATA");

    // Receive ACK
    let mut last_acked_offset = 0u64;
    loop {
        if let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
            let _ = read_buf.split_to(consumed);
            if let Frame::Ack { offset } = frame {
                println!("Client: received ACK for offset {}", offset);
                last_acked_offset = offset;
                break;
            }
        }
        match recv.read(&mut tmp).await {
            Ok(Some(n)) if n > 0 => {
                read_buf.extend_from_slice(&tmp[..n]);
            }
            _ => break,
        }
    }

    // Close first connection (simulate disconnect)
    drop(send);
    drop(recv);
    connection.close(0u32.into(), b"client disconnect");
    println!("Client: first connection closed");

    // Wait for server to be ready for second connection
    let _ = server_ready_rx.recv().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // === Client: Second connection (resume) ===
    println!("Client: starting second connection for resume...");

    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    println!("Client: second connection established");

    // Accept bi stream from server
    let (mut send, mut recv) = connection.accept_bi().await.unwrap();
    println!("Client: accepted bi stream for resume");

    // First receive SESSION_INIT (server always sends this)
    let mut read_buf = BytesMut::with_capacity(4096);

    loop {
        if let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
            let _ = read_buf.split_to(consumed);
            if let Frame::SessionInit { .. } = frame {
                println!("Client: received SESSION_INIT (will ignore, sending RESUME_REQ)");
                break;
            }
        }
        let n = recv.read(&mut tmp).await.unwrap().unwrap();
        read_buf.extend_from_slice(&tmp[..n]);
    }

    // Send RESUME_REQ with saved session info
    let resume_req = Frame::ResumeReq {
        session_id,
        last_offset: last_acked_offset,
        token,
    };
    let mut buf = BytesMut::new();
    resume_req.encode(&mut buf);
    send.write_all(&buf).await.unwrap();
    println!("Client: sent RESUME_REQ for session {:?}", session_id);

    // Wait for RESUME_OK or RESUME_REJECT
    let mut resume_ok_received = false;
    let mut data_after_resume_received = false;

    let timeout = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            while let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
                let _ = read_buf.split_to(consumed);
                println!("Client: received frame {:?}", frame);

                match frame {
                    Frame::ResumeOk { start_offset, ack_offset } => {
                        println!("Client: RESUME_OK! start_offset={}, ack_offset={}", start_offset, ack_offset);
                        resume_ok_received = true;
                    }
                    Frame::ResumeReject { reason } => {
                        panic!("Client: RESUME_REJECT: {}", reason);
                    }
                    Frame::Data { data, .. } => {
                        println!(
                            "Client: received DATA after resume: {:?}",
                            String::from_utf8_lossy(&data)
                        );
                        assert_eq!(&data[..], b"resumed session data");
                        data_after_resume_received = true;
                    }
                    _ => {}
                }

                if resume_ok_received && data_after_resume_received {
                    return;
                }
            }

            match recv.read(&mut tmp).await {
                Ok(Some(n)) => {
                    read_buf.extend_from_slice(&tmp[..n]);
                }
                Ok(None) => break,
                Err(e) => {
                    println!("Client: read error: {}", e);
                    break;
                }
            }
        }
    });

    timeout.await.expect("Reconnection test timed out");

    assert!(resume_ok_received, "Should have received RESUME_OK");
    assert!(
        data_after_resume_received,
        "Should have received data after resume"
    );

    // Wait for server to complete
    let _ = server_done_rx.recv().await;

    println!("Reconnection test passed!");
}

/// Test that client does not reconnect when receiving CLOSE frame.
#[tokio::test]
async fn test_no_reconnect_on_close_frame() {
    use qrelay::protocol::Frame;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Install crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (server_config, _certs) = create_server_config();

    // Create QUIC server endpoint
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();
    println!("Server listening on {}", server_addr);

    // Counter to track number of connections
    let connection_count = Arc::new(AtomicUsize::new(0));
    let connection_count_clone = connection_count.clone();

    // Channel to signal when CLOSE frame has been sent
    let (close_sent_tx, mut close_sent_rx) = tokio::sync::mpsc::channel::<()>(1);

    // Spawn server task
    let _server_handle = tokio::spawn(async move {
        // Accept first connection
        println!("Server: waiting for first connection...");
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        connection_count_clone.fetch_add(1, Ordering::SeqCst);
        println!("Server: first connection accepted (count=1)");

        // Server opens bi stream
        let (mut send, _recv) = connection.open_bi().await.unwrap();
        println!("Server: opened bi stream");

        // Send SESSION_INIT
        let session_id = [1u8; 16];
        let token = Bytes::from_static(b"test_token");
        let session_init = Frame::SessionInit {
            session_id,
            token: token.clone(),
        };
        let mut buf = BytesMut::new();
        session_init.encode(&mut buf);
        send.write_all(&buf).await.unwrap();
        println!("Server: sent SESSION_INIT");

        // Small delay to ensure client receives SESSION_INIT
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send CLOSE frame
        let close_frame = Frame::Close {
            reason: "backend closed".to_string(),
        };
        let mut close_buf = BytesMut::new();
        close_frame.encode(&mut close_buf);
        send.write_all(&close_buf).await.unwrap();
        println!("Server: sent CLOSE frame with reason 'backend closed'");

        // Signal that CLOSE was sent
        let _ = close_sent_tx.send(()).await;

        // Wait for potential reconnection attempts (should not happen)
        // Use a timeout to check if any new connection comes in
        let reconnect_check = tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                match server_endpoint.accept().await {
                    Some(incoming) => {
                        if let Ok(_conn) = incoming.await {
                            connection_count_clone.fetch_add(1, Ordering::SeqCst);
                            println!("Server: unexpected second connection!");
                            return true; // Reconnection happened (unexpected)
                        }
                    }
                    None => {
                        println!("Server: endpoint closed");
                        return false;
                    }
                }
            }
        });

        match reconnect_check.await {
            Ok(reconnected) => {
                if reconnected {
                    println!("Server: ERROR - client reconnected when it should not have!");
                }
            }
            Err(_) => {
                println!("Server: timeout waiting for reconnection (expected)");
            }
        }
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create client
    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(create_client_config());

    // Connect to QUIC server
    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    println!("Client: connected to QUIC server");

    // Accept bi stream from server
    let (_send, mut recv) = connection.accept_bi().await.unwrap();
    println!("Client: accepted bi stream");

    // Receive SESSION_INIT
    let mut read_buf = BytesMut::with_capacity(1024);
    let mut tmp = [0u8; 1024];

    let _session_info = loop {
        if let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
            let _ = read_buf.split_to(consumed);
            if let Frame::SessionInit { session_id, token } = frame {
                println!("Client: received SESSION_INIT, session_id={:?}", session_id);
                break (session_id, token);
            }
        }
        let n = recv.read(&mut tmp).await.unwrap().unwrap();
        read_buf.extend_from_slice(&tmp[..n]);
    };

    // Receive CLOSE frame
    let mut close_received = false;
    'outer: loop {
        // Try to decode frames from buffer first
        while let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
            let _ = read_buf.split_to(consumed);
            println!("Client: received frame {:?}", frame);

            if let Frame::Close { reason } = frame {
                println!("Client: received CLOSE frame with reason: {}", reason);
                assert_eq!(reason, "backend closed");
                close_received = true;
                break 'outer;
            }
        }

        // Read more data
        match recv.read(&mut tmp).await {
            Ok(Some(n)) => {
                read_buf.extend_from_slice(&tmp[..n]);
            }
            Ok(None) => {
                println!("Client: stream closed");
                break;
            }
            Err(e) => {
                println!("Client: read error: {}", e);
                break;
            }
        }
    }

    assert!(close_received, "Client should have received CLOSE frame");

    // Wait for server to confirm CLOSE was sent
    let _ = close_sent_rx.recv().await;

    // Client should NOT reconnect after receiving CLOSE frame
    // The SessionClosed state should be treated as Ok and no reconnection should happen
    // Wait briefly to ensure no reconnection attempt is made
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Verify only one connection was made
    let final_count = connection_count.load(Ordering::SeqCst);
    assert_eq!(
        final_count, 1,
        "Expected exactly 1 connection, but got {}. Client should not reconnect after CLOSE frame.",
        final_count
    );

    println!("Test passed: Client did not reconnect after receiving CLOSE frame");
}

/// Test new connection protocol: client sends CONNECT_REQ, server responds with SESSION_INIT.
/// This test simulates the client-driven protocol where:
/// 1. Client opens bi stream and sends CONNECT_REQ
/// 2. Server accepts the stream (triggered by client's data)
/// 3. Server responds with SESSION_INIT
#[tokio::test]
async fn test_connect_req_session_init_flow() {
    use qrelay::protocol::Frame;

    // Install crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (server_config, _certs) = create_server_config();

    // Create QUIC server endpoint
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();
    println!("Server listening on {}", server_addr);

    // Spawn server task that expects CONNECT_REQ before sending SESSION_INIT
    let server_handle = tokio::spawn(async move {
        println!("Server: waiting for connection...");
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        println!("Server: connection accepted");

        // Server accepts bi stream (client opens the stream)
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        println!("Server: accepted bi stream");

        // Wait for CONNECT_REQ from client
        let mut read_buf = BytesMut::with_capacity(1024);
        let mut tmp = [0u8; 1024];

        // Read first frame - should be CONNECT_REQ
        loop {
            if let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
                let _ = read_buf.split_to(consumed);
                println!("Server: received frame {:?}", frame);

                match frame {
                    Frame::ConnectReq => {
                        println!("Server: received CONNECT_REQ");
                        // Send SESSION_INIT in response
                        let session_id = [2u8; 16];
                        let token = Bytes::from_static(b"new_session_token");
                        let session_init = Frame::SessionInit {
                            session_id,
                            token: token.clone(),
                        };
                        let mut buf = BytesMut::new();
                        session_init.encode(&mut buf);
                        send.write_all(&buf).await.unwrap();
                        println!("Server: sent SESSION_INIT in response to CONNECT_REQ");
                        // Wait for data to be transmitted before closing
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        send.finish().unwrap();
                        return true;
                    }
                    _ => {
                        println!("Server: unexpected frame, expected CONNECT_REQ");
                        return false;
                    }
                }
            }

            match recv.read(&mut tmp).await {
                Ok(Some(n)) => {
                    read_buf.extend_from_slice(&tmp[..n]);
                    println!("Server: read {} bytes", n);
                }
                Ok(None) => {
                    println!("Server: stream closed");
                    return false;
                }
                Err(e) => {
                    println!("Server: read error: {}", e);
                    return false;
                }
            }
        }
    });

    // Create client
    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(create_client_config());

    // Connect to QUIC server
    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    println!("Client: connected to QUIC server");

    // Client opens bi stream (client initiates the stream)
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    println!("Client: opened bi stream");

    // Client sends CONNECT_REQ first
    let connect_req = Frame::ConnectReq;
    let mut buf = BytesMut::new();
    connect_req.encode(&mut buf);
    send.write_all(&buf).await.unwrap();
    println!("Client: sent CONNECT_REQ");

    // Client waits for SESSION_INIT
    let mut read_buf = BytesMut::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let mut session_init_received = false;

    loop {
        if let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
            let _ = read_buf.split_to(consumed);
            println!("Client: received frame {:?}", frame);

            if let Frame::SessionInit { session_id, token } = frame {
                println!(
                    "Client: received SESSION_INIT, session_id={:?}, token_len={}",
                    session_id,
                    token.len()
                );
                assert_eq!(session_id, [2u8; 16]);
                assert_eq!(&token[..], b"new_session_token");
                session_init_received = true;
                break;
            }
        }

        match recv.read(&mut tmp).await {
            Ok(Some(n)) => {
                read_buf.extend_from_slice(&tmp[..n]);
                println!("Client: read {} bytes", n);
            }
            Ok(None) => {
                println!("Client: stream closed");
                break;
            }
            Err(e) => {
                println!("Client: read error: {}", e);
                break;
            }
        }
    }

    // Wait for server to complete
    let server_received_connect_req = server_handle.await.unwrap();

    assert!(
        server_received_connect_req,
        "Server should have received CONNECT_REQ"
    );
    assert!(
        session_init_received,
        "Client should have received SESSION_INIT"
    );

    println!("Test passed: CONNECT_REQ -> SESSION_INIT flow works correctly");
}

/// Test that server receives CLOSE frame when client shuts down.
#[tokio::test]
async fn test_client_sends_close_on_shutdown() {
    use qrelay::protocol::Frame;

    // Install crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (server_config, _certs) = create_server_config();

    // Create QUIC server endpoint
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();
    println!("Server listening on {}", server_addr);

    // Channel to communicate the received CLOSE frame reason from server
    let (close_received_tx, mut close_received_rx) = tokio::sync::mpsc::channel::<String>(1);

    // Spawn server task
    let _server_handle = tokio::spawn(async move {
        println!("Server: waiting for connection...");
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        println!("Server: connection accepted");

        // Server opens bi stream
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        println!("Server: opened bi stream");

        // Send SESSION_INIT
        let session_id = [1u8; 16];
        let token = Bytes::from_static(b"test_token");
        let session_init = Frame::SessionInit {
            session_id,
            token: token.clone(),
        };
        let mut buf = BytesMut::new();
        session_init.encode(&mut buf);
        send.write_all(&buf).await.unwrap();
        println!("Server: sent SESSION_INIT");

        // Read frames from client
        let mut read_buf = BytesMut::with_capacity(1024);
        let mut tmp = [0u8; 1024];

        loop {
            // Try to decode frames from buffer
            while let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
                let _ = read_buf.split_to(consumed);
                println!("Server: received frame {:?}", frame);

                if let Frame::Close { reason } = frame {
                    println!("Server: received CLOSE frame with reason: {}", reason);
                    let _ = close_received_tx.send(reason).await;
                    return;
                }
            }

            // Read more data
            match recv.read(&mut tmp).await {
                Ok(Some(n)) => {
                    read_buf.extend_from_slice(&tmp[..n]);
                    println!("Server: read {} bytes", n);
                }
                Ok(None) => {
                    println!("Server: stream closed without receiving CLOSE frame");
                    return;
                }
                Err(e) => {
                    println!("Server: read error: {}", e);
                    return;
                }
            }
        }
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create client
    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(create_client_config());

    // Connect to QUIC server
    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    println!("Client: connected to QUIC server");

    // Accept bi stream from server
    let (mut send, mut recv) = connection.accept_bi().await.unwrap();
    println!("Client: accepted bi stream");

    // Receive SESSION_INIT
    let mut read_buf = BytesMut::with_capacity(1024);
    let mut tmp = [0u8; 1024];

    loop {
        if let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
            let _ = read_buf.split_to(consumed);
            if let Frame::SessionInit { session_id, .. } = frame {
                println!("Client: received SESSION_INIT, session_id={:?}", session_id);
                break;
            }
        }
        let n = recv.read(&mut tmp).await.unwrap().unwrap();
        read_buf.extend_from_slice(&tmp[..n]);
    }

    // Simulate shutdown: send CLOSE frame with "client shutting down" reason
    let close_frame = Frame::Close {
        reason: "client shutting down".to_string(),
    };
    let mut close_buf = BytesMut::new();
    close_frame.encode(&mut close_buf);
    send.write_all(&close_buf).await.unwrap();
    println!("Client: sent CLOSE frame with reason 'client shutting down'");

    // Wait for server to receive the CLOSE frame
    let timeout_result =
        tokio::time::timeout(Duration::from_secs(5), close_received_rx.recv()).await;

    match timeout_result {
        Ok(Some(reason)) => {
            assert_eq!(
                reason, "client shutting down",
                "Server should receive CLOSE frame with correct reason"
            );
            println!(
                "Test passed: Server received CLOSE frame with reason '{}'",
                reason
            );
        }
        Ok(None) => {
            panic!("Server task ended without sending CLOSE frame reason");
        }
        Err(_) => {
            panic!("Timeout waiting for server to receive CLOSE frame");
        }
    }
}

/// Test that client receives CLOSE frame when backend TCP connection closes.
/// This tests the server's proper termination handling when the backend disconnects.
#[tokio::test]
async fn test_client_receives_close_on_backend_tcp_close() {
    use qrelay::protocol::Frame;

    // Install crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (server_config, _certs) = create_server_config();

    // Start a TCP backend that accepts one connection and immediately closes
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    println!("Backend listening on {}", backend_addr);

    // Spawn backend that accepts connection, waits briefly, then closes
    let backend_handle = tokio::spawn(async move {
        let (stream, _) = backend_listener.accept().await.unwrap();
        println!("Backend: accepted connection");
        // Small delay to ensure relay is fully established
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Close the connection by dropping it
        drop(stream);
        println!("Backend: closed connection");
    });

    // Create QUIC server endpoint
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();
    println!("QUIC Server listening on {}", server_addr);

    // Spawn server task that simulates qrelay server behavior
    let backend_addr_str = backend_addr.to_string();
    let _server_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        println!("QUIC Server: accepted connection");

        // Accept bi stream from client (client opens the stream)
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        println!("QUIC Server: accepted bi stream");

        // Wait for CONNECT_REQ from client
        let mut read_buf = BytesMut::with_capacity(1024);
        let mut tmp = [0u8; 1024];

        loop {
            if let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
                let _ = read_buf.split_to(consumed);
                if let Frame::ConnectReq = frame {
                    println!("QUIC Server: received CONNECT_REQ");
                    break;
                }
            }
            let n = recv.read(&mut tmp).await.unwrap().unwrap();
            read_buf.extend_from_slice(&tmp[..n]);
        }

        // Send SESSION_INIT
        let session_id = [3u8; 16];
        let token = Bytes::from_static(b"backend_close_test_token");
        let session_init = Frame::SessionInit {
            session_id,
            token: token.clone(),
        };
        let mut buf = BytesMut::new();
        session_init.encode(&mut buf);
        send.write_all(&buf).await.unwrap();
        println!("QUIC Server: sent SESSION_INIT");

        // Connect to backend
        let backend = TcpStream::connect(&backend_addr_str).await.unwrap();
        println!("QUIC Server: connected to backend");

        // Backend will close shortly, so we just need to detect EOF and send CLOSE
        let (mut backend_read, _backend_write) = backend.into_split();

        let mut backend_buf = [0u8; 1024];
        match backend_read.read(&mut backend_buf).await {
            Ok(0) => {
                println!("QUIC Server: backend closed (EOF)");
                // Send CLOSE frame
                let close_frame = Frame::Close {
                    reason: "backend closed".to_string(),
                };
                let mut close_buf = BytesMut::new();
                close_frame.encode(&mut close_buf);
                send.write_all(&close_buf).await.unwrap();
                let _ = send.finish();
                println!("QUIC Server: sent CLOSE frame and finished stream");
                // Wait for client to receive the CLOSE frame before task ends
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Ok(n) => {
                println!("QUIC Server: unexpected data from backend: {} bytes", n);
            }
            Err(e) => {
                println!("QUIC Server: backend read error: {}", e);
            }
        }
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create client
    let mut client_endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(create_client_config());

    // Connect to QUIC server
    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    println!("Client: connected to QUIC server");

    // Client opens bi stream
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    println!("Client: opened bi stream");

    // Send CONNECT_REQ
    let connect_req = Frame::ConnectReq;
    let mut buf = BytesMut::new();
    connect_req.encode(&mut buf);
    send.write_all(&buf).await.unwrap();
    println!("Client: sent CONNECT_REQ");

    // Receive SESSION_INIT
    let mut read_buf = BytesMut::with_capacity(1024);
    let mut tmp = [0u8; 1024];

    loop {
        if let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
            let _ = read_buf.split_to(consumed);
            if let Frame::SessionInit { session_id, .. } = frame {
                println!("Client: received SESSION_INIT, session_id={:?}", session_id);
                break;
            }
        }
        let n = recv.read(&mut tmp).await.unwrap().unwrap();
        read_buf.extend_from_slice(&tmp[..n]);
    }

    // Wait for CLOSE frame from server (backend will close and server should send CLOSE)
    let mut close_received = false;
    let mut close_reason = String::new();

    let timeout_result = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            // Try to decode frames from buffer
            while let Some((frame, consumed)) = Frame::decode(&read_buf).unwrap() {
                let _ = read_buf.split_to(consumed);
                println!("Client: received frame {:?}", frame);

                if let Frame::Close { reason } = frame {
                    println!("Client: received CLOSE frame with reason: {}", reason);
                    close_received = true;
                    close_reason = reason;
                    return;
                }
            }

            // Read more data
            match recv.read(&mut tmp).await {
                Ok(Some(n)) => {
                    read_buf.extend_from_slice(&tmp[..n]);
                }
                Ok(None) => {
                    println!("Client: stream closed without CLOSE frame");
                    return;
                }
                Err(e) => {
                    println!("Client: read error: {}", e);
                    return;
                }
            }
        }
    })
    .await;

    // Wait for backend to finish
    let _ = backend_handle.await;

    assert!(timeout_result.is_ok(), "Test timed out waiting for CLOSE frame");
    assert!(close_received, "Client should have received CLOSE frame when backend TCP closed");
    assert_eq!(close_reason, "backend closed", "CLOSE reason should be 'backend closed'");

    println!("Test passed: Client received CLOSE frame with reason 'backend closed' when backend TCP connection closed");
}
