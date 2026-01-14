# qrelay Technical Documentation

## Architecture

qrelay consists of three modes of operation:

| Mode     | Description                                                        |
| -------- | ------------------------------------------------------------------ |
| `server` | Server-side proxy: accepts QUIC connections, relays to backend TCP |
| `client` | Client-side proxy: listens on TCP, connects to QUIC server         |
| `nc`     | stdin/stdout mode for SSH ProxyCommand                             |

### Data Flow

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   Application   │      │     qrelay      │      │   Application   │
│    (Client)     │      │                 │      │    (Server)     │
├─────────────────┤      ├─────────────────┤      ├─────────────────┤
│                 │ TCP  │ Client   Server │ TCP  │                 │
│                 │─────>│ Proxy    Proxy  │─────>│                 │
│                 │      │                 │      │                 │
│                 │<─────│        QUIC     │<─────│                 │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

---

## CLI Reference

### Global Flags

| Flag          | Type   | Default | Description                                                                      |
| ------------- | ------ | ------- | -------------------------------------------------------------------------------- |
| `--log-level` | string | `info`  | Log level (`debug`\|`info`\|`warn`\|`error`). Defaults to `error` for `nc` mode. |

### `qrelay server`

Start server-side proxy.

```
qrelay server --listen <addr> --backend <host:port> [flags]
```

| Flag                 | Type     | Required | Default           | Description                                |
| -------------------- | -------- | -------- | ----------------- | ------------------------------------------ |
| `--listen`           | string   | Yes      | -                 | QUIC listen address (e.g., `:9443`)        |
| `--backend`          | string   | Yes      | -                 | Backend TCP address (e.g., `127.0.0.1:22`) |
| `--tls-cert`         | string   | No       | auto              | TLS certificate file path                  |
| `--tls-key`          | string   | No       | auto              | TLS private key file path                  |
| `--alpn`             | string   | No       | `qrelay/1`        | ALPN protocol identifier                   |
| `--idle-timeout`     | duration | No       | `10s`             | QUIC idle timeout                          |
| `--keep-alive`       | duration | No       | `3s`              | QUIC keep-alive interval (`0` to disable)  |
| `--max-buffer-bytes` | int64    | No       | `67108864` (64MB) | Deep buffer limit                          |
| `--resume-max-age`   | duration | No       | `168h` (7 days)   | Session resume max age                     |
| `--config-dir`       | string   | No       | see below         | Configuration directory                    |

**Config Directory**:
- root (UID=0): `/etc/qrelay`
- others: `~/.qrelay`

**Certificate Auto-generation**: If `--tls-cert` and `--tls-key` are not specified, a self-signed ECDSA P-256 certificate (1 year validity) is generated in the config directory.

### `qrelay client`

Start client-side proxy.

```
qrelay client --listen <addr> --connect <host:port> [flags]
```

| Flag                     | Type     | Required | Default           | Description                               |
| ------------------------ | -------- | -------- | ----------------- | ----------------------------------------- |
| `--listen`               | string   | Yes      | -                 | Local TCP listen address (e.g., `:2222`)  |
| `--connect`              | string   | Yes      | -                 | QUIC server address (e.g., `server:9443`) |
| `--sni`                  | string   | No       | -                 | TLS SNI hostname                          |
| `--ca`                   | string   | No       | -                 | Root CA certificate file path             |
| `--insecure-skip-verify` | bool     | No       | `false`           | Disable certificate verification          |
| `--fingerprint`          | string   | No       | -                 | Public key fingerprint (SHA-256 hex)      |
| `--alpn`                 | string   | No       | `qrelay/1`        | ALPN protocol identifier                  |
| `--idle-timeout`         | duration | No       | `10s`             | QUIC idle timeout                         |
| `--keep-alive`           | duration | No       | `3s`              | QUIC keep-alive interval                  |
| `--reconnect-interval`   | duration | No       | `1s`              | Reconnect interval                        |
| `--max-buffer-bytes`     | int64    | No       | `67108864` (64MB) | Deep buffer limit                         |

### `qrelay nc`

stdin/stdout proxy for SSH ProxyCommand.

```
qrelay nc --connect <host:port> [flags]
```

Same flags as `client` except `--listen`.

### `qrelay version`

Display version information.

```
qrelay version 1.0.0
  commit: abc1234
  built:  2025-01-01T00:00:00Z
```

---

## Security Modes

Client-side TLS verification modes:

| Mode        | Condition                 | Description                                       |
| ----------- | ------------------------- | ------------------------------------------------- |
| CA          | Default                   | Verify against CA certificates (system or custom) |
| Fingerprint | `--fingerprint` specified | Verify public key fingerprint                     |
| None        | `--insecure-skip-verify`  | No verification (development only)                |

### CA Mode (Default)

```bash
# Use system CA
qrelay client --listen :2222 --connect server:9443

# Use custom CA
qrelay client --listen :2222 --connect server:9443 --ca ./ca.pem
```

### Fingerprint Mode

Recommended for self-signed certificates.

```bash
qrelay client --listen :2222 --connect server:9443 \
  --fingerprint aa:bb:cc:dd:ee:ff:...
```

Fingerprint formats:
- Colon-separated: `aa:bb:cc:dd:...` (95 characters)
- Continuous hex: `aabbccdd...` (64 characters)

Case-insensitive.

### Insecure Mode

**Warning**: Development/testing only. Never use in production.

```bash
qrelay client --listen :2222 --connect server:9443 --insecure-skip-verify
```

---

## Exit Codes

For `client` and `nc` modes:

| Code | Description             |
| ---- | ----------------------- |
| 0    | Success                 |
| 10   | Listen failed           |
| 11   | QUIC connection failed  |
| 12   | TLS verification failed |
| 20   | Buffer limit exceeded   |
| 21   | Resume rejected         |

---

## Wire Protocol

### Frame Format (TLV)

```
+------------+------------+------------------+
| Frame Type | Length     | Payload          |
| (1 byte)   | (varint)   | (variable)       |
+------------+------------+------------------+
```

### Frame Types

| Type          | Value | Payload                                                                |
| ------------- | ----- | ---------------------------------------------------------------------- |
| DATA          | 0x01  | offset(varint) + data                                                  |
| ACK           | 0x02  | offset(varint)                                                         |
| RESUME_REQ    | 0x03  | session_id(16 bytes) + last_offset(varint) + token_len(varint) + token |
| RESUME_OK     | 0x04  | start_offset(varint)                                                   |
| RESUME_REJECT | 0x05  | reason_len(varint) + reason                                            |
| CLOSE         | 0x06  | reason_len(varint) + reason                                            |
| SESSION_INIT  | 0x07  | session_id(16 bytes) + token_len(varint) + token                       |

### Session States

```
     ┌──────────────────────────────────────┐
     │                                      │
     v                                      │
  ┌──────┐    ┌────────┐    ┌──────────────┐│
  │ INIT │───>│ ACTIVE │───>│ DISCONNECTED ││
  └──────┘    └────────┘    └──────────────┘│
                  ^                │        │
                  │                v        │
                  │         ┌──────────┐    │
                  └─────────│ RESUMING │────┘
                            └──────────┘
                                 │
                                 v
                            ┌────────┐
                            │ CLOSED │
                            └────────┘
```

### Connection Flow

**New Connection:**
```
Client                    Server
   |                         |
   |<----QUIC Connection---->|
   |                         |
   |<---SESSION_INIT---------|  (Server initiates stream)
   |                         |
   |<--------DATA----------->|  (Bidirectional relay)
   |<--------ACK------------>|
   |                         |
```

**Session Resume:**
```
Client                    Server
   |                         |
   |<----QUIC Connection---->|
   |                         |
   |<---SESSION_INIT---------|
   |---RESUME_REQ----------->|  (Client wants to resume)
   |<--RESUME_OK-------------|  (or RESUME_REJECT)
   |                         |
   |<--------DATA----------->|  (Continue from last offset)
```

---

## Deep Buffer

qrelay maintains send and receive buffers to handle reconnections:

- **Send Buffer**: Retains sent data until acknowledged by peer
- **Receive Buffer**: Reorders out-of-order data and tracks acknowledgments

On reconnection, unacknowledged data is retransmitted from the last known offset.

Default buffer size: 64MB per direction, configurable via `--max-buffer-bytes`.

---

## Configuration Examples

### SSH via qrelay

```bash
# Server
qrelay server --listen :9443 --backend 127.0.0.1:22

# Client (TCP proxy)
qrelay client --listen :2222 --connect server.example.com:9443 \
  --fingerprint <fingerprint>
ssh -p 2222 user@127.0.0.1

# Client (ProxyCommand)
ssh -o ProxyCommand='qrelay nc --connect server.example.com:9443 --fingerprint <fp>' user@server
```

### ~/.ssh/config

```
Host myserver
  HostName server.example.com
  User myuser
  ProxyCommand qrelay nc --connect %h:9443 --fingerprint aa:bb:cc:...
```

### systemd Service

```ini
[Unit]
Description=qrelay SSH proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/qrelay server --listen :9443 --backend 127.0.0.1:22
Restart=always

[Install]
WantedBy=multi-user.target
```

---

## Signal Handling

- `SIGINT` (Ctrl+C): Graceful shutdown
  - Closes active sessions with CLOSE frame
  - Waits for pending operations to complete

---

## Implementation Notes

The following areas use well-tested libraries:

| Area        | Library           | Reason                        |
| ----------- | ----------------- | ----------------------------- |
| QUIC        | quinn             | Protocol complexity, security |
| TLS/Crypto  | rustls, aws-lc-rs | Security critical             |
| CLI Parsing | clap              | Edge case handling            |
| Logging     | tracing           | Structured logging            |
