# PyGuard Pro README

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)

## Overview
PyGuard Pro is a real-time, rule-based Intrusion Detection System (IDS) and advanced network packet analyzer. It captures network packets, extracts and stores all protocol details (Ethernet, IP, TCP, UDP, ICMP, ARP, DNS, HTTP, and more) in a database, and provides both summary and detailed inspection features, similar to Wireshark.

## Features
- Real-time packet capture (Scapy)
- Deep protocol inspection (Ethernet, IP, TCP, UDP, ICMP, ARP, DNS, HTTP, etc.)
- Stores all protocol fields as JSON in the database
- Packet summary and detailed inspection (Wireshark-like)
- Rule/statistics-based intrusion detection
- Database logging
- Web dashboard (planned)

## Quick Start
1. **Clone the repository:**
   ```powershell
   git clone <your-repo-url>
   cd intrudex
   ```
2. **Set up a virtual environment (recommended):**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
3. **Install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```
4. **Run the packet sniffer:**
   ```powershell
   python packet_sniffer.py -c 10
   ```
5. **View captured packets and inspect details:**
   ```powershell
   python view_packets.py
   # Enter a row number to see full protocol details for a packet
   ```

## Contributing
Contributions are welcome! Please open issues or pull requests. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Issues
If you find a bug or have a feature request, please open an issue on GitHub.

## Code of Conduct
This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## Team Roles
- **A**: Packet Capture & DB Integration (Backend)
- **B**: Detection Engine & Data Analysis
- **C**: Web Dashboard & UI/UX (Frontend & DevOps)

## Documentation
See the `docs/` folder for project scope, team plan, and feature roadmap.

## Sample Output
```
Source IP: 192.168.1.2 -> Destination IP: 8.8.8.8 | Protocol: ICMP | Size: 98 | Details: {"icmp_type": 8, "icmp_code": 0, ...}
Source IP: 10.0.0.5 -> Destination IP: 192.168.1.1 | Protocol: TCP | Src Port: 443 -> Dst Port: 52344 | Size: 74 | Details: {"tcp_flags": "S", "tcp_seq": 123456, ...}
```

## License
MIT License (add your license file if needed)
