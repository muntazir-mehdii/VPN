# Academic VPN Project

> A production-style VPN implementation demonstrating modular cryptographic architecture, FastAPI backend, WebSocket tunneling, and Wintun driver integration — built for academic research in network security and secure communication systems.

---

## Project Highlights

| Component | Technology |
|-----------|-----------|
| Backend Server | FastAPI + WebSocket |
| Cryptography | AES, DES/3DES, RSA, SHA-256 |
| Tunneling | Wintun virtual network adapter (Windows) |
| Protocol | WireGuard wrapper |
| Interface | CLI-only (no frontend) |
| Language | Python 3.11 |

---

## What This Project Does

Simulates a simplified but architecturally realistic VPN system including:

- **Encrypted tunnel** between a VPN client and server
- **Modular crypto engine** — AES, DES/3DES, RSA, SHA-256 implemented from scratch
- **WebSocket control channel** for real-time client-server communication
- **FastAPI backend** orchestrating tunnel lifecycle
- **Wintun driver integration** for Windows TUN adapter support

The architecture mirrors real-world VPN systems while remaining readable and extensible for academic study.

---

## Repository Structure

```
Academic-VPN/
├── backend/
│   ├── server.py               # FastAPI server + tunnel orchestration
│   ├── vpn_client.py           # CLI VPN client
│   └── requirements.txt
├── core/
│   ├── aes.py                  # AES encryption module
│   ├── des.py                  # DES / 3DES encryption module
│   ├── rsa.py                  # RSA key operations
│   ├── hashing.py              # SHA-256 utilities
│   ├── signatures.py           # Digital signature support
│   ├── wireguard_wrapper.py    # WireGuard integration
│   └── wintun_wrapper.py       # Wintun driver interface
├── docs/
│   ├── technical_manual.md     # Full architecture documentation
│   ├── defense_presentation.md # Academic defense notes
│   └── chacha20_plan.md        # Planned ChaCha20 implementation
├── wintun/                     # Windows TUN driver resources
├── tests/
│   └── demo_crypto.py          # Crypto module verification scripts
├── launch_vpn.py
├── run_server.py
├── START_SERVER.bat
└── START_VPN_ADMIN.bat
```

---

## Quick Start

### 1. Setup environment

```bash
# Python 3.11 recommended
python -m venv venv
.\venv\Scripts\Activate.ps1        # Windows PowerShell
pip install -r backend/requirements.txt
```

### 2. Start the VPN server

```bash
python -m backend.server

# Alternatives
python run_server.py
START_SERVER.bat
```

### 3. Connect the VPN client

```bash
python backend/vpn_client.py

# Alternatives
python launch_vpn.py
START_VPN_ADMIN.bat        # Run as Administrator for Wintun access
```

---

## Cryptographic Modules

All crypto is implemented modularly in `core/` — each algorithm is isolated and independently testable:

```
core/aes.py          → AES-128/256 encryption & decryption
core/des.py          → DES and 3DES block cipher
core/rsa.py          → RSA key generation, encrypt, decrypt
core/hashing.py      → SHA-256 digest utilities
core/signatures.py   → Digital signature creation & verification
```

Run verification tests:

```bash
python tests/demo_crypto.py
```

---

## Architecture Overview

```
VPN Client (CLI)
      │
      │  WebSocket (control channel)
      ▼
FastAPI Backend Server
      │
      ├── Crypto Engine (AES / RSA / SHA-256)
      │
      └── Wintun Adapter → TUN Interface → Encrypted Tunnel
```

---

## Current Status

- ✅ All cryptographic modules implemented and verified
- ✅ FastAPI backend server operational
- ✅ WebSocket control channel (client ↔ server)
- ✅ Wintun virtual adapter integration
- ✅ CLI-based connection management
- 🔄 ChaCha20 implementation planned (`docs/chacha20_plan.md`)

**Known limitations:**
- DES test vectors diverge from official FIPS vectors (functional for demonstration)
- Tunnel features simplified for educational scope
- Some production-grade features (key rotation, NAT traversal) not implemented

---

## Documentation

| File | Contents |
|------|----------|
| `docs/technical_manual.md` | Full architecture & design decisions |
| `docs/defense_presentation.md` | Academic defense walkthrough |
| `docs/chacha20_plan.md` | Roadmap for ChaCha20 stream cipher |
| `wintun/README.md` | Wintun driver setup & usage |

---

## Tech Stack

`Python 3.11` `FastAPI` `WebSockets` `Wintun` `WireGuard` `AES` `RSA` `SHA-256`

---

## Author

**Muntazir Mehdi** — CS Student, NUST SEECS  
Developed as part of an academic networking & security project to demonstrate VPN architecture, cryptographic design, and secure communication pipelines.

[GitHub](https://github.com/muntazir-mehdii) · [Upwork](https://www.upwork.com/freelancers/~015ab18bf2700e35b7)
