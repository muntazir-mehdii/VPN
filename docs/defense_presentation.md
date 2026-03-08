# Academic Defense: CipherGuard VPN

## Slide 1: Introduction
- **Project Title**: CipherGuard VPN
- **Objective**: Develop a modular, educational VPN to demonstrate cryptographic primitives in a network context.
- **Key Features**: Hot-swappable ciphers (AES/DES), real-time traffic monitoring, transparency.

## Slide 2: Architecture
- **Diagram**: [Frontend] <-> [FastAPI Backend] <-> [Tunnel Service] <-> [Core Crypto]
- **Design Pattern**: Modular Strategy Pattern for Ciphers.
- **Tech Stack**: Python (Backend/Crypto), Vanilla JS + Tailwind (Frontend).

## Slide 3: Cryptography Deep Dive (AES)
- Explain AES-128 structure (SubBytes, MixColumns).
- Show code snippet from `core/aes.py`.
- **Demo**: Show "Verified" status in dashboard.

## Slide 4: Legacy Support (DES/3DES)
- Explain the Feistel Network.
- Discuss DES insecurity (56-bit key) vs 3DES.
- **Live Demo**: Switch Algo to DES, show traffic still flows (encrypted).

## Slide 5: Performance & Visualization
- Explain WebSocket telemetry (how bandwidth is measured).
- Show the Live Traffic Graph.

## Slide 6: Challenges & Solutions
- **Challenge**: Implementing AES MixColumns correctly in Python.
- **Solution**: Used Galois Field multiplication helper (gf_mul).
- **Challenge**: Real-time updates without polling.
- **Solution**: Implemented WebSockets for push-based state sync.

## Slide 7: Conclusion
- Summary of achievements.
- Future work: RSA Key Exchange, TUN/TAP driver integration.
