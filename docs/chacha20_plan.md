# ChaCha20 Implementation Plan

## Goal
Add ChaCha20 stream cipher to the VPN to demonstrate modern, high-performance cryptography (used by WireGuard).

## Changes
1.  **Core**: Create `core/chacha20.py`.
    *   Implement the Quarter Round function.
    *   Implement the Block function.
    *   Implement XOR stream generation.
2.  **Backend**: Update `backend/tunnel.py` to support `CHACHA20` algo.
3.  **Frontend**: Update `index.html` dropdown and adds "Stream Cipher" badge.

## Technical Details
- **Key Size**: 32 bytes (256 bits).
- **Nonce**: 12 bytes (96 bits).
- **Counter**: 4 bytes (32 bits).
