# qrelay

Reconnectable, order-guaranteed, lossless byte stream TCP proxy using QUIC.

## Overview

qrelay is a TCP proxy that uses QUIC for proxy-to-proxy communication, providing:

- **Automatic reconnection** from temporary disconnections
- **Order-guaranteed, lossless** byte stream delivery
- **Connection migration** and NAT rebinding tolerance
- **Deep buffering** to retain unacknowledged data across reconnections

```
[ Application ]
      |
      | TCP
      v
[ Client Proxy ]
      |
      | QUIC (reconnectable / connection migration)
      v
[ Server Proxy ]
      |
      | TCP
      v
[ Application ]
```

## Installation

```bash
cargo build --release
```

## Quick Start

### Server

```bash
# Start server proxy (forwards to local SSH)
qrelay server --listen :9443 --backend 127.0.0.1:22
```

On first run, a self-signed certificate is generated and the SHA-256 fingerprint is displayed.

### Client (TCP Proxy Mode)

```bash
# Start client proxy
qrelay client --listen :2222 --connect server.example.com:9443 \
  --fingerprint aa:bb:cc:...

# Connect via local port
ssh -p 2222 user@127.0.0.1
```

### Client (SSH ProxyCommand Mode)

```bash
# Direct SSH connection via qrelay
ssh -o ProxyCommand='qrelay nc --connect server.example.com:9443 --fingerprint aa:bb:cc:...' user@server
```

Or in `~/.ssh/config`:

```
Host myserver
  HostName server.example.com
  User myuser
  ProxyCommand qrelay nc --connect %h:9443 --fingerprint aa:bb:cc:...
```
