Academic VPN Project

A production-style academic VPN implementation developed by Muntazir Mehdi.
The project demonstrates a modular VPN architecture combining custom cryptography modules, a FastAPI backend, and CLI-based client/server interaction.

The system is designed for educational and research purposes, focusing on understanding VPN tunnel architecture, encryption mechanisms, and secure communication pipelines.

All interaction is performed through the command line interface (CLI).
No frontend UI is used.

Project Overview

This project simulates a simplified VPN system that includes:

Secure communication between a VPN client and server

Modular cryptographic implementations

A FastAPI-based backend server

A WebSocket control channel for communication

Integration with the Wintun driver for tunneling support on Windows

The architecture is structured to mimic real-world VPN systems while remaining understandable for academic study and experimentation.

Quick Start (CLI Only)
1. Create and activate virtual environment

Python 3.11 recommended

Windows PowerShell:

python -m venv venv
.\venv\Scripts\Activate.ps1
2. Install dependencies
pip install -r backend/requirements.txt
3. Run the VPN server
python -m backend.server

Alternative launchers:

python run_server.py
START_SERVER.bat
4. Run the VPN client
python backend/vpn_client.py

Alternative launchers:

python launch_vpn.py
START_VPN_ADMIN.bat
Project Structure
backend/
    FastAPI server, tunnel orchestration, WebSocket control channel

core/
    Cryptographic modules (AES, DES/3DES, RSA, hashing, signatures)
    WireGuard wrapper
    Wintun wrapper

docs/
    Technical documentation, architecture notes, defense presentation

wintun/
    Windows TUN driver resources and documentation

launch_vpn.py
run_server.py
START_*.bat
    Convenience scripts for launching the VPN
Core Features

Modular cryptographic implementations

AES encryption support

DES / 3DES encryption modules

RSA key-based operations

SHA-256 hashing utilities

WebSocket-based control communication

CLI-based VPN client management

FastAPI server architecture

Integration with the Wintun virtual network adapter

Current Status

Core cryptographic modules implemented and verified.

FastAPI backend server operational.

WebSocket communication between client and server implemented.

CLI-based workflow for VPN connection management.

Testing scripts available in:

tests/demo_crypto.py
Known Limitations

DES test vectors differ from official FIPS vectors (works for demonstration).

VPN tunnel features are simplified for educational purposes.

Some advanced production VPN features are not implemented.

Documentation

Detailed technical information is available in:

docs/technical_manual.md
docs/defense_presentation.md
docs/chacha20_plan.md

Wintun driver documentation:

wintun/README.md
Author

Muntazir Mehdi

This project was developed as part of an academic networking/security project to demonstrate VPN architecture, cryptographic design, and secure communication systems.