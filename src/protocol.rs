//! Wire protocol implementation for qrelay.
//!
//! This module implements a TLV (Type-Length-Value) frame format for
//! proxy-to-proxy communication.

use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

/// Frame type constants.
const FRAME_DATA: u8 = 0x01;
const FRAME_ACK: u8 = 0x02;
const FRAME_RESUME_REQ: u8 = 0x03;
const FRAME_RESUME_OK: u8 = 0x04;
const FRAME_RESUME_REJECT: u8 = 0x05;
const FRAME_CLOSE: u8 = 0x06;
const FRAME_SESSION_INIT: u8 = 0x07;
const FRAME_CONNECT_REQ: u8 = 0x08;

/// Session ID size in bytes.
const SESSION_ID_SIZE: usize = 16;

/// Maximum varint size in bytes (for u64).
const MAX_VARINT_SIZE: usize = 10;

/// Protocol error types.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("invalid frame type: {0:#x}")]
    InvalidFrameType(u8),

    #[error("varint overflow")]
    VarintOverflow,

    #[error("incomplete data")]
    IncompleteData,

    #[error("invalid utf-8 in reason string")]
    InvalidUtf8,
}

/// Result type for protocol operations.
pub type ProtocolResult<T> = std::result::Result<T, ProtocolError>;

/// Wire protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Data frame with offset and payload.
    Data { offset: u64, data: Bytes },
    /// Acknowledgement frame.
    Ack { offset: u64 },
    /// Resume request frame.
    ResumeReq {
        session_id: [u8; 16],
        last_offset: u64,
        token: Bytes,
    },
    /// Resume accepted response.
    /// - start_offset: Offset from which server will retransmit data to client
    /// - ack_offset: Highest offset server has received from client (for client retransmission)
    ResumeOk { start_offset: u64, ack_offset: u64 },
    /// Resume rejected response.
    ResumeReject { reason: String },
    /// Connection close frame.
    Close { reason: String },
    /// Session initialization frame (server -> client).
    SessionInit {
        session_id: [u8; 16],
        token: Bytes,
    },
    /// Connection request frame (client -> server, new connection).
    ConnectReq,
}

/// Encode a u64 value as a varint.
///
/// Uses MSB as continuation flag, lower 7 bits for data.
pub fn encode_varint(mut value: u64, buf: &mut BytesMut) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.put_u8(byte);
        if value == 0 {
            break;
        }
    }
}

/// Decode a varint from a buffer.
///
/// Returns `Ok(None)` if there isn't enough data.
/// Returns `Err(VarintOverflow)` if the varint is too large.
pub fn decode_varint(buf: &mut &[u8]) -> ProtocolResult<Option<u64>> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;

    for i in 0..MAX_VARINT_SIZE {
        if buf.is_empty() {
            return Ok(None);
        }

        let byte = buf[0];
        *buf = &buf[1..];

        let value = (byte & 0x7F) as u64;

        // Check for overflow before shifting
        if shift >= 64 || (shift == 63 && value > 1) {
            return Err(ProtocolError::VarintOverflow);
        }

        result |= value << shift;
        shift += 7;

        if byte & 0x80 == 0 {
            return Ok(Some(result));
        }

        // If we've read the maximum number of bytes and still have continuation bit
        if i == MAX_VARINT_SIZE - 1 {
            return Err(ProtocolError::VarintOverflow);
        }
    }

    Err(ProtocolError::VarintOverflow)
}

/// Calculate the encoded size of a varint.
fn varint_size(value: u64) -> usize {
    if value == 0 {
        return 1;
    }
    let bits = 64 - value.leading_zeros();
    bits.div_ceil(7) as usize
}

impl Frame {
    /// Encode this frame to a byte buffer.
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Frame::Data { offset, data } => {
                buf.put_u8(FRAME_DATA);
                let payload_len = varint_size(*offset) + data.len();
                encode_varint(payload_len as u64, buf);
                encode_varint(*offset, buf);
                buf.put_slice(data);
            }
            Frame::Ack { offset } => {
                buf.put_u8(FRAME_ACK);
                let payload_len = varint_size(*offset);
                encode_varint(payload_len as u64, buf);
                encode_varint(*offset, buf);
            }
            Frame::ResumeReq {
                session_id,
                last_offset,
                token,
            } => {
                buf.put_u8(FRAME_RESUME_REQ);
                let payload_len =
                    SESSION_ID_SIZE + varint_size(*last_offset) + varint_size(token.len() as u64) + token.len();
                encode_varint(payload_len as u64, buf);
                buf.put_slice(session_id);
                encode_varint(*last_offset, buf);
                encode_varint(token.len() as u64, buf);
                buf.put_slice(token);
            }
            Frame::ResumeOk { start_offset, ack_offset } => {
                buf.put_u8(FRAME_RESUME_OK);
                let payload_len = varint_size(*start_offset) + varint_size(*ack_offset);
                encode_varint(payload_len as u64, buf);
                encode_varint(*start_offset, buf);
                encode_varint(*ack_offset, buf);
            }
            Frame::ResumeReject { reason } => {
                buf.put_u8(FRAME_RESUME_REJECT);
                let reason_bytes = reason.as_bytes();
                let payload_len = varint_size(reason_bytes.len() as u64) + reason_bytes.len();
                encode_varint(payload_len as u64, buf);
                encode_varint(reason_bytes.len() as u64, buf);
                buf.put_slice(reason_bytes);
            }
            Frame::Close { reason } => {
                buf.put_u8(FRAME_CLOSE);
                let reason_bytes = reason.as_bytes();
                let payload_len = varint_size(reason_bytes.len() as u64) + reason_bytes.len();
                encode_varint(payload_len as u64, buf);
                encode_varint(reason_bytes.len() as u64, buf);
                buf.put_slice(reason_bytes);
            }
            Frame::SessionInit { session_id, token } => {
                buf.put_u8(FRAME_SESSION_INIT);
                let payload_len = SESSION_ID_SIZE + varint_size(token.len() as u64) + token.len();
                encode_varint(payload_len as u64, buf);
                buf.put_slice(session_id);
                encode_varint(token.len() as u64, buf);
                buf.put_slice(token);
            }
            Frame::ConnectReq => {
                buf.put_u8(FRAME_CONNECT_REQ);
                encode_varint(0, buf); // No payload
            }
        }
    }

    /// Decode a frame from a byte buffer.
    ///
    /// Returns `Ok(None)` if there isn't enough data to decode a complete frame.
    /// On success, returns the decoded frame and the number of bytes consumed.
    pub fn decode(buf: &[u8]) -> ProtocolResult<Option<(Frame, usize)>> {
        if buf.is_empty() {
            return Ok(None);
        }

        let frame_type = buf[0];
        let mut remaining = &buf[1..];
        let start_len = remaining.len();

        // Decode payload length
        let length = match decode_varint(&mut remaining)? {
            Some(len) => len as usize,
            None => return Ok(None),
        };

        let header_size = 1 + (start_len - remaining.len());

        // Check if we have enough data for the payload
        if remaining.len() < length {
            return Ok(None);
        }

        let payload = &remaining[..length];
        let total_consumed = header_size + length;

        let frame = Self::decode_payload(frame_type, payload)?;

        Ok(Some((frame, total_consumed)))
    }

    /// Decode the payload based on frame type.
    fn decode_payload(frame_type: u8, payload: &[u8]) -> ProtocolResult<Frame> {
        let mut buf = payload;

        match frame_type {
            FRAME_DATA => {
                let offset = decode_varint(&mut buf)?.ok_or(ProtocolError::IncompleteData)?;
                let data = Bytes::copy_from_slice(buf);
                Ok(Frame::Data { offset, data })
            }
            FRAME_ACK => {
                let offset = decode_varint(&mut buf)?.ok_or(ProtocolError::IncompleteData)?;
                Ok(Frame::Ack { offset })
            }
            FRAME_RESUME_REQ => {
                if buf.len() < SESSION_ID_SIZE {
                    return Err(ProtocolError::IncompleteData);
                }
                let mut session_id = [0u8; SESSION_ID_SIZE];
                session_id.copy_from_slice(&buf[..SESSION_ID_SIZE]);
                buf = &buf[SESSION_ID_SIZE..];

                let last_offset = decode_varint(&mut buf)?.ok_or(ProtocolError::IncompleteData)?;
                let token_len =
                    decode_varint(&mut buf)?.ok_or(ProtocolError::IncompleteData)? as usize;

                if buf.len() < token_len {
                    return Err(ProtocolError::IncompleteData);
                }
                let token = Bytes::copy_from_slice(&buf[..token_len]);

                Ok(Frame::ResumeReq {
                    session_id,
                    last_offset,
                    token,
                })
            }
            FRAME_RESUME_OK => {
                let start_offset = decode_varint(&mut buf)?.ok_or(ProtocolError::IncompleteData)?;
                let ack_offset = decode_varint(&mut buf)?.ok_or(ProtocolError::IncompleteData)?;
                Ok(Frame::ResumeOk { start_offset, ack_offset })
            }
            FRAME_RESUME_REJECT => {
                let reason_len =
                    decode_varint(&mut buf)?.ok_or(ProtocolError::IncompleteData)? as usize;
                if buf.len() < reason_len {
                    return Err(ProtocolError::IncompleteData);
                }
                let reason = std::str::from_utf8(&buf[..reason_len])
                    .map_err(|_| ProtocolError::InvalidUtf8)?
                    .to_string();
                Ok(Frame::ResumeReject { reason })
            }
            FRAME_CLOSE => {
                let reason_len =
                    decode_varint(&mut buf)?.ok_or(ProtocolError::IncompleteData)? as usize;
                if buf.len() < reason_len {
                    return Err(ProtocolError::IncompleteData);
                }
                let reason = std::str::from_utf8(&buf[..reason_len])
                    .map_err(|_| ProtocolError::InvalidUtf8)?
                    .to_string();
                Ok(Frame::Close { reason })
            }
            FRAME_SESSION_INIT => {
                if buf.len() < SESSION_ID_SIZE {
                    return Err(ProtocolError::IncompleteData);
                }
                let mut session_id = [0u8; SESSION_ID_SIZE];
                session_id.copy_from_slice(&buf[..SESSION_ID_SIZE]);
                buf = &buf[SESSION_ID_SIZE..];

                let token_len =
                    decode_varint(&mut buf)?.ok_or(ProtocolError::IncompleteData)? as usize;

                if buf.len() < token_len {
                    return Err(ProtocolError::IncompleteData);
                }
                let token = Bytes::copy_from_slice(&buf[..token_len]);

                Ok(Frame::SessionInit { session_id, token })
            }
            FRAME_CONNECT_REQ => {
                // No payload to decode
                Ok(Frame::ConnectReq)
            }
            _ => Err(ProtocolError::InvalidFrameType(frame_type)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encode_decode_zero() {
        let mut buf = BytesMut::new();
        encode_varint(0, &mut buf);
        assert_eq!(&buf[..], &[0x00]);

        let mut slice: &[u8] = &buf;
        let decoded = decode_varint(&mut slice).unwrap().unwrap();
        assert_eq!(decoded, 0);
    }

    #[test]
    fn test_varint_encode_decode_single_byte() {
        let mut buf = BytesMut::new();
        encode_varint(127, &mut buf);
        assert_eq!(&buf[..], &[0x7F]);

        let mut slice: &[u8] = &buf;
        let decoded = decode_varint(&mut slice).unwrap().unwrap();
        assert_eq!(decoded, 127);
    }

    #[test]
    fn test_varint_encode_decode_two_bytes() {
        let mut buf = BytesMut::new();
        encode_varint(128, &mut buf);
        assert_eq!(&buf[..], &[0x80, 0x01]);

        let mut slice: &[u8] = &buf;
        let decoded = decode_varint(&mut slice).unwrap().unwrap();
        assert_eq!(decoded, 128);
    }

    #[test]
    fn test_varint_encode_decode_large() {
        let mut buf = BytesMut::new();
        let value = 0xFFFF_FFFF_FFFF_FFFF_u64;
        encode_varint(value, &mut buf);

        let mut slice: &[u8] = &buf;
        let decoded = decode_varint(&mut slice).unwrap().unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_varint_incomplete() {
        let buf: &[u8] = &[0x80]; // Continuation bit set but no more data
        let mut slice = buf;
        let result = decode_varint(&mut slice).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_varint_empty() {
        let buf: &[u8] = &[];
        let mut slice = buf;
        let result = decode_varint(&mut slice).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_frame_data_roundtrip() {
        let frame = Frame::Data {
            offset: 12345,
            data: Bytes::from_static(b"hello world"),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let (decoded, consumed) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_frame_ack_roundtrip() {
        let frame = Frame::Ack { offset: 99999 };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let (decoded, consumed) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_frame_resume_req_roundtrip() {
        let frame = Frame::ResumeReq {
            session_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            last_offset: 1000,
            token: Bytes::from_static(b"auth_token_here"),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let (decoded, consumed) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_frame_resume_ok_roundtrip() {
        let frame = Frame::ResumeOk {
            start_offset: 500,
            ack_offset: 1200,
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let (decoded, consumed) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_frame_resume_reject_roundtrip() {
        let frame = Frame::ResumeReject {
            reason: "session expired".to_string(),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let (decoded, consumed) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_frame_close_roundtrip() {
        let frame = Frame::Close {
            reason: "goodbye".to_string(),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let (decoded, consumed) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_frame_data_empty_payload() {
        let frame = Frame::Data {
            offset: 0,
            data: Bytes::new(),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let (decoded, consumed) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_frame_close_empty_reason() {
        let frame = Frame::Close {
            reason: String::new(),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let (decoded, consumed) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_decode_incomplete_header() {
        let buf: &[u8] = &[];
        let result = Frame::decode(buf).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_decode_incomplete_length() {
        let buf: &[u8] = &[0x01, 0x80]; // Frame type + incomplete varint
        let result = Frame::decode(buf).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_decode_incomplete_payload() {
        let buf: &[u8] = &[0x01, 0x10, 0x00]; // Frame type + length 16 + only 1 byte
        let result = Frame::decode(buf).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_decode_invalid_frame_type() {
        let buf: &[u8] = &[0xFF, 0x01, 0x00]; // Invalid frame type
        let result = Frame::decode(buf);
        assert_eq!(result, Err(ProtocolError::InvalidFrameType(0xFF)));
    }

    #[test]
    fn test_decode_invalid_utf8() {
        // Build a CLOSE frame with invalid UTF-8
        let mut buf = BytesMut::new();
        buf.put_u8(FRAME_CLOSE);
        encode_varint(3, &mut buf); // payload length: 1 (len varint) + 2 (invalid bytes)
        encode_varint(2, &mut buf); // reason length
        buf.put_slice(&[0xFF, 0xFE]); // invalid UTF-8

        let result = Frame::decode(&buf);
        assert_eq!(result, Err(ProtocolError::InvalidUtf8));
    }

    #[test]
    fn test_multiple_frames_in_buffer() {
        let frame1 = Frame::Ack { offset: 100 };
        let frame2 = Frame::Ack { offset: 200 };

        let mut buf = BytesMut::new();
        frame1.encode(&mut buf);
        frame2.encode(&mut buf);

        let (decoded1, consumed1) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(decoded1, frame1);

        let (decoded2, consumed2) = Frame::decode(&buf[consumed1..]).unwrap().unwrap();
        assert_eq!(decoded2, frame2);
        assert_eq!(consumed1 + consumed2, buf.len());
    }

    #[test]
    fn test_varint_size() {
        assert_eq!(varint_size(0), 1);
        assert_eq!(varint_size(127), 1);
        assert_eq!(varint_size(128), 2);
        assert_eq!(varint_size(16383), 2);
        assert_eq!(varint_size(16384), 3);
        assert_eq!(varint_size(u64::MAX), 10);
    }

    #[test]
    fn test_frame_resume_req_empty_token() {
        let frame = Frame::ResumeReq {
            session_id: [0; 16],
            last_offset: 0,
            token: Bytes::new(),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let (decoded, consumed) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_frame_data_large_offset() {
        let frame = Frame::Data {
            offset: u64::MAX,
            data: Bytes::from_static(b"test"),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let (decoded, consumed) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_frame_session_init_roundtrip() {
        let frame = Frame::SessionInit {
            session_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            token: Bytes::from_static(b"resume_token"),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let (decoded, consumed) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_frame_session_init_empty_token() {
        let frame = Frame::SessionInit {
            session_id: [0; 16],
            token: Bytes::new(),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        let (decoded, consumed) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_frame_connect_req_roundtrip() {
        let frame = Frame::ConnectReq;

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);

        // ConnectReq encodes to: type (1 byte) + length varint (1 byte for 0)
        assert_eq!(buf.len(), 2);
        assert_eq!(buf[0], FRAME_CONNECT_REQ);
        assert_eq!(buf[1], 0x00); // length = 0

        let (decoded, consumed) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, buf.len());
    }
}
