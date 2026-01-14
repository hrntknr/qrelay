//! Session management for qrelay server.
//!
//! This module provides session state management for QUIC connections,
//! including support for session resumption after reconnection.

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex as TokioMutex;

use crate::buffer::{RecvBuffer, SendBuffer, SessionState};

/// Backend stream halves stored for session resumption.
pub struct BackendStream {
    /// Read half of the backend TCP connection.
    pub read_half: Arc<TokioMutex<OwnedReadHalf>>,
    /// Write half of the backend TCP connection.
    pub write_half: Arc<TokioMutex<OwnedWriteHalf>>,
}

impl std::fmt::Debug for BackendStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendStream")
            .field("read_half", &"<OwnedReadHalf>")
            .field("write_half", &"<OwnedWriteHalf>")
            .finish()
    }
}

/// Session ID size in bytes.
pub const SESSION_ID_SIZE: usize = 16;

/// A session representing a single client connection.
#[derive(Debug)]
pub struct Session {
    /// Unique session identifier.
    id: [u8; SESSION_ID_SIZE],
    /// Current session state.
    state: SessionState,
    /// Buffer for outgoing data (server -> client).
    send_buffer: SendBuffer,
    /// Buffer for incoming data (client -> server).
    recv_buffer: RecvBuffer,
    /// Resume token for session verification.
    token: Bytes,
    /// Time when this session was created.
    created_at: Instant,
}

impl Session {
    /// Creates a new session with the specified buffer size limit.
    pub fn new(max_buffer_bytes: u64) -> Self {
        let id = generate_session_id();
        let token = generate_resume_token(&id);

        Self {
            id,
            state: SessionState::Init,
            send_buffer: SendBuffer::new(max_buffer_bytes),
            recv_buffer: RecvBuffer::new(max_buffer_bytes),
            token,
            created_at: Instant::now(),
        }
    }

    /// Returns the session ID.
    pub fn id(&self) -> &[u8; SESSION_ID_SIZE] {
        &self.id
    }

    /// Returns the current session state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Sets the session state.
    pub fn set_state(&mut self, state: SessionState) {
        self.state = state;
    }

    /// Returns the resume token for this session.
    pub fn generate_resume_token(&self) -> Bytes {
        self.token.clone()
    }

    /// Verifies a resume token against this session's token.
    pub fn verify_resume_token(&self, token: &Bytes) -> bool {
        self.token == *token
    }

    /// Returns the time when this session was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns a mutable reference to the send buffer.
    pub fn send_buffer_mut(&mut self) -> &mut SendBuffer {
        &mut self.send_buffer
    }

    /// Returns a reference to the send buffer.
    pub fn send_buffer(&self) -> &SendBuffer {
        &self.send_buffer
    }

    /// Returns a mutable reference to the receive buffer.
    pub fn recv_buffer_mut(&mut self) -> &mut RecvBuffer {
        &mut self.recv_buffer
    }

    /// Returns a reference to the receive buffer.
    pub fn recv_buffer(&self) -> &RecvBuffer {
        &self.recv_buffer
    }
}

/// Generates a random session ID.
fn generate_session_id() -> [u8; SESSION_ID_SIZE] {
    let mut id = [0u8; SESSION_ID_SIZE];
    // Use getrandom for cryptographically secure random bytes
    getrandom::getrandom(&mut id).expect("failed to generate random session ID");
    id
}

/// Generates a resume token for the given session ID.
fn generate_resume_token(session_id: &[u8; SESSION_ID_SIZE]) -> Bytes {
    use sha2::{Digest, Sha256};

    let mut random_bytes = [0u8; 32];
    getrandom::getrandom(&mut random_bytes).expect("failed to generate random token bytes");

    let mut hasher = Sha256::new();
    hasher.update(session_id);
    hasher.update(&random_bytes);
    let hash = hasher.finalize();

    Bytes::copy_from_slice(&hash)
}

/// Manages active and disconnected sessions.
#[derive(Debug)]
pub struct SessionManager {
    /// Active sessions indexed by session ID.
    sessions: HashMap<[u8; SESSION_ID_SIZE], Session>,
    /// Backend streams for session resumption.
    backend_streams: HashMap<[u8; SESSION_ID_SIZE], BackendStream>,
    /// Maximum age for session resumption.
    resume_max_age: Duration,
}

impl SessionManager {
    /// Creates a new session manager with the specified resume max age.
    pub fn new(resume_max_age: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            backend_streams: HashMap::new(),
            resume_max_age,
        }
    }

    /// Creates a new session and returns its ID and resume token.
    pub fn create_session(&mut self, max_buffer_bytes: u64) -> ([u8; SESSION_ID_SIZE], Bytes) {
        let session = Session::new(max_buffer_bytes);
        let id = *session.id();
        let token = session.generate_resume_token();
        self.sessions.insert(id, session);
        (id, token)
    }

    /// Gets a mutable reference to a session by ID.
    pub fn get_session(&mut self, id: &[u8; SESSION_ID_SIZE]) -> Option<&mut Session> {
        self.sessions.get_mut(id)
    }

    /// Gets an immutable reference to a session by ID.
    pub fn get_session_ref(&self, id: &[u8; SESSION_ID_SIZE]) -> Option<&Session> {
        self.sessions.get(id)
    }

    /// Tries to resume a session.
    ///
    /// Returns `(start_offset, ack_offset)` on success:
    /// - `start_offset`: Offset from which server will retransmit data to client
    /// - `ack_offset`: Highest offset server has received from client (for client retransmission)
    pub fn try_resume(
        &mut self,
        id: &[u8; SESSION_ID_SIZE],
        token: &Bytes,
        last_offset: u64,
    ) -> Result<(u64, u64), String> {
        let session = self
            .sessions
            .get_mut(id)
            .ok_or_else(|| "session not found".to_string())?;

        // Check if session is too old
        if session.created_at.elapsed() > self.resume_max_age {
            return Err("session expired".to_string());
        }

        // Verify token
        if !session.verify_resume_token(token) {
            return Err("invalid token".to_string());
        }

        // Check session state - explicit handling for each state
        match session.state {
            SessionState::Init => {
                return Err("session not yet active: cannot resume from Init state".to_string());
            }
            SessionState::Active => {
                // Connection takeover: allow resuming from an active session
                // This handles the case where the client reconnects before the server
                // detects the previous connection is lost
                session.set_state(SessionState::Resuming);
            }
            SessionState::Disconnected => {
                // Normal resume: session was disconnected and client is reconnecting
                session.set_state(SessionState::Resuming);
            }
            SessionState::Resuming => {
                return Err("session is already being resumed".to_string());
            }
            SessionState::Closed => {
                return Err("session has been closed and cannot be resumed".to_string());
            }
        }

        // Calculate the start offset for server->client retransmission
        // The client reports last_offset (highest ACKed offset they received from server)
        // We need to retransmit from that point
        let server_acked_offset = session.send_buffer.acked_offset();
        let start_offset = if last_offset > server_acked_offset {
            last_offset
        } else {
            server_acked_offset
        };

        // Get the ack_offset for client->server retransmission
        // This is the highest offset server has received from client
        let ack_offset = session.recv_buffer.acked_offset();

        Ok((start_offset, ack_offset))
    }

    /// Removes a session and its associated backend stream.
    pub fn remove_session(&mut self, id: &[u8; SESSION_ID_SIZE]) -> Option<Session> {
        self.backend_streams.remove(id);
        self.sessions.remove(id)
    }

    /// Cleans up expired sessions.
    pub fn cleanup_expired(&mut self) {
        let resume_max_age = self.resume_max_age;
        let mut expired_ids = Vec::new();
        self.sessions.retain(|id, session| {
            let age = session.created_at.elapsed();
            let keep = age <= resume_max_age || session.state == SessionState::Active;
            if !keep {
                tracing::debug!(
                    session_id = ?session.id(),
                    age_secs = age.as_secs(),
                    "removing expired session"
                );
                expired_ids.push(*id);
            }
            keep
        });
        // Also remove backend streams for expired sessions
        for id in expired_ids {
            self.backend_streams.remove(&id);
        }
    }

    /// Stores a backend stream for a session.
    pub fn store_backend_stream(&mut self, id: &[u8; SESSION_ID_SIZE], stream: BackendStream) {
        self.backend_streams.insert(*id, stream);
    }

    /// Takes the backend stream for a session (removes it from storage).
    pub fn take_backend_stream(&mut self, id: &[u8; SESSION_ID_SIZE]) -> Option<BackendStream> {
        self.backend_streams.remove(id)
    }

    /// Checks if a backend stream exists for a session.
    pub fn has_backend_stream(&self, id: &[u8; SESSION_ID_SIZE]) -> bool {
        self.backend_streams.contains_key(id)
    }

    /// Returns the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_new() {
        let session = Session::new(1024);
        assert_eq!(session.state(), SessionState::Init);
        assert_eq!(session.id().len(), SESSION_ID_SIZE);
        assert!(!session.generate_resume_token().is_empty());
    }

    #[test]
    fn test_session_state_transitions() {
        let mut session = Session::new(1024);
        assert_eq!(session.state(), SessionState::Init);

        session.set_state(SessionState::Active);
        assert_eq!(session.state(), SessionState::Active);

        session.set_state(SessionState::Disconnected);
        assert_eq!(session.state(), SessionState::Disconnected);

        session.set_state(SessionState::Resuming);
        assert_eq!(session.state(), SessionState::Resuming);

        session.set_state(SessionState::Closed);
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn test_session_token_verification() {
        let session = Session::new(1024);
        let token = session.generate_resume_token();

        assert!(session.verify_resume_token(&token));
        assert!(!session.verify_resume_token(&Bytes::from_static(b"invalid")));
    }

    #[test]
    fn test_session_id_uniqueness() {
        let session1 = Session::new(1024);
        let session2 = Session::new(1024);
        assert_ne!(session1.id(), session2.id());
    }

    #[test]
    fn test_session_manager_new() {
        let manager = SessionManager::new(Duration::from_secs(3600));
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn test_session_manager_create_session() {
        let mut manager = SessionManager::new(Duration::from_secs(3600));
        let (id, token) = manager.create_session(1024);

        assert_eq!(manager.session_count(), 1);
        assert!(manager.get_session(&id).is_some());
        assert!(!token.is_empty());
    }

    #[test]
    fn test_session_manager_get_session() {
        let mut manager = SessionManager::new(Duration::from_secs(3600));
        let (id, _token) = manager.create_session(1024);

        let session = manager.get_session(&id).unwrap();
        assert_eq!(session.id(), &id);

        let invalid_id = [0u8; SESSION_ID_SIZE];
        assert!(manager.get_session(&invalid_id).is_none());
    }

    #[test]
    fn test_session_manager_try_resume_success() {
        let mut manager = SessionManager::new(Duration::from_secs(3600));
        let (id, _) = manager.create_session(1024);

        // Get token and set state to disconnected
        let token = {
            let session = manager.get_session(&id).unwrap();
            session.set_state(SessionState::Disconnected);
            session.generate_resume_token()
        };

        let result = manager.try_resume(&id, &token, 0);
        assert!(result.is_ok());

        let session = manager.get_session(&id).unwrap();
        assert_eq!(session.state(), SessionState::Resuming);
    }

    #[test]
    fn test_session_manager_try_resume_invalid_token() {
        let mut manager = SessionManager::new(Duration::from_secs(3600));
        let (id, _) = manager.create_session(1024);

        {
            let session = manager.get_session(&id).unwrap();
            session.set_state(SessionState::Disconnected);
        }

        let invalid_token = Bytes::from_static(b"invalid");
        let result = manager.try_resume(&id, &invalid_token, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid token"));
    }

    #[test]
    fn test_session_manager_try_resume_not_found() {
        let mut manager = SessionManager::new(Duration::from_secs(3600));
        let invalid_id = [0u8; SESSION_ID_SIZE];
        let token = Bytes::from_static(b"token");

        let result = manager.try_resume(&invalid_id, &token, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_session_manager_try_resume_closed_session() {
        let mut manager = SessionManager::new(Duration::from_secs(3600));
        let (id, _) = manager.create_session(1024);

        let token = {
            let session = manager.get_session(&id).unwrap();
            session.set_state(SessionState::Closed);
            session.generate_resume_token()
        };

        let result = manager.try_resume(&id, &token, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("closed"));
    }

    #[test]
    fn test_session_manager_try_resume_active_session() {
        let mut manager = SessionManager::new(Duration::from_secs(3600));
        let (id, _) = manager.create_session(1024);

        let token = {
            let session = manager.get_session(&id).unwrap();
            session.set_state(SessionState::Active);
            session.generate_resume_token()
        };

        // Resume from ACTIVE state should succeed (connection takeover)
        let result = manager.try_resume(&id, &token, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_manager_remove_session() {
        let mut manager = SessionManager::new(Duration::from_secs(3600));
        let (id, _) = manager.create_session(1024);

        assert_eq!(manager.session_count(), 1);
        let removed = manager.remove_session(&id);
        assert!(removed.is_some());
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn test_session_manager_cleanup_expired() {
        let mut manager = SessionManager::new(Duration::from_millis(1));
        let (id, _) = manager.create_session(1024);

        // Set to disconnected state
        {
            let session = manager.get_session(&id).unwrap();
            session.set_state(SessionState::Disconnected);
        }

        // Wait for session to expire
        std::thread::sleep(Duration::from_millis(10));

        manager.cleanup_expired();
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn test_session_manager_cleanup_keeps_active() {
        let mut manager = SessionManager::new(Duration::from_millis(1));
        let (id, _) = manager.create_session(1024);

        // Set to active state
        {
            let session = manager.get_session(&id).unwrap();
            session.set_state(SessionState::Active);
        }

        // Wait for potential expiry
        std::thread::sleep(Duration::from_millis(10));

        // Active sessions should be kept
        manager.cleanup_expired();
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_session_buffers() {
        let mut session = Session::new(1024);

        // Test send buffer
        let offset = session.send_buffer_mut().push(Bytes::from_static(b"hello")).unwrap();
        assert_eq!(offset, 0);
        assert_eq!(session.send_buffer().buffered_bytes(), 5);

        // Test receive buffer
        session.recv_buffer_mut().insert(0, Bytes::from_static(b"world")).unwrap();
        assert_eq!(session.recv_buffer().buffered_bytes(), 5);
    }

    #[test]
    fn test_session_manager_try_resume_init_state() {
        let mut manager = SessionManager::new(Duration::from_secs(3600));
        let (id, _) = manager.create_session(1024);

        // Session is in Init state by default
        let token = {
            let session = manager.get_session(&id).unwrap();
            assert_eq!(session.state(), SessionState::Init);
            session.generate_resume_token()
        };

        // Resume from INIT state should fail
        let result = manager.try_resume(&id, &token, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Init"));
    }

    #[test]
    fn test_session_manager_try_resume_resuming_state() {
        let mut manager = SessionManager::new(Duration::from_secs(3600));
        let (id, _) = manager.create_session(1024);

        let token = {
            let session = manager.get_session(&id).unwrap();
            session.set_state(SessionState::Resuming);
            session.generate_resume_token()
        };

        // Resume from RESUMING state should fail
        let result = manager.try_resume(&id, &token, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already being resumed"));
    }

    /// Tests that a session that was closed due to receiving a CLOSE frame
    /// (Error::SessionClosed in server.rs sets state to Closed) cannot be resumed.
    /// This verifies the fix where SessionClosed error transitions state to Closed
    /// instead of Disconnected.
    #[test]
    fn test_session_closed_by_close_frame_cannot_resume() {
        let mut manager = SessionManager::new(Duration::from_secs(3600));
        let (id, _) = manager.create_session(1024);

        // Simulate the server.rs behavior:
        // 1. Session becomes Active when relay starts
        // 2. Client sends CLOSE frame -> Error::SessionClosed is returned
        // 3. Server sets session state to Closed (not Disconnected)
        let token = {
            let session = manager.get_session(&id).unwrap();
            session.set_state(SessionState::Active);
            session.generate_resume_token()
        };

        // Simulate what server.rs does when Error::SessionClosed occurs:
        // match &result {
        //     Err(Error::SessionClosed(_)) => session.set_state(SessionState::Closed),
        //     ...
        // }
        {
            let session = manager.get_session(&id).unwrap();
            session.set_state(SessionState::Closed);
        }

        // Attempt to resume should fail because session is Closed
        let result = manager.try_resume(&id, &token, 0);
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("closed"),
            "Expected error message to contain 'closed', got: {}",
            err_msg
        );
    }

    /// Tests that a session in Disconnected state can be resumed,
    /// but a session in Closed state cannot.
    /// This is the key distinction made by the fix.
    #[test]
    fn test_disconnected_vs_closed_session_resume_behavior() {
        let mut manager = SessionManager::new(Duration::from_secs(3600));

        // Create two sessions
        let (id1, _) = manager.create_session(1024);
        let (id2, _) = manager.create_session(1024);

        // Get tokens while setting states
        let token1 = {
            let session = manager.get_session(&id1).unwrap();
            session.set_state(SessionState::Active);
            session.generate_resume_token()
        };
        let token2 = {
            let session = manager.get_session(&id2).unwrap();
            session.set_state(SessionState::Active);
            session.generate_resume_token()
        };

        // Session 1: Set to Disconnected (e.g., network error)
        {
            let session = manager.get_session(&id1).unwrap();
            session.set_state(SessionState::Disconnected);
        }

        // Session 2: Set to Closed (e.g., received CLOSE frame)
        {
            let session = manager.get_session(&id2).unwrap();
            session.set_state(SessionState::Closed);
        }

        // Disconnected session CAN be resumed
        let result1 = manager.try_resume(&id1, &token1, 0);
        assert!(
            result1.is_ok(),
            "Disconnected session should be resumable, got: {:?}",
            result1
        );

        // Closed session CANNOT be resumed
        let result2 = manager.try_resume(&id2, &token2, 0);
        assert!(
            result2.is_err(),
            "Closed session should not be resumable"
        );
        assert!(result2.unwrap_err().contains("closed"));
    }
}
