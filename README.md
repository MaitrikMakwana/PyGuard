# PyGuard: Python Desktop Network Analyzer & ML-based Host Intrusion Detection

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)

## Overview
PyGuard is a modern Python desktop application for real-time network packet capture, storage, analysis, and host-based intrusion detection using machine learning. Built with PyQt5, it provides an interactive GUI for live monitoring, filtering, protocol inspection, statistics, and ML-driven threat alerts—all in one place.

## Features
- **Real-time packet capture** (Scapy backend)
- **Deep protocol inspection** (Ethernet, IP, TCP, UDP, ICMP, ARP, DNS, HTTP, etc.)
- **Database storage** of all protocol fields (SQLite)
- **Wireshark-like summary and detailed inspection**
- **ML-based intrusion detection** (host-based, supports scikit-learn models)
- **Interactive desktop GUI** (PyQt5)
- **Live statistics, filtering, and export/import (CSV/PCAP)**
- **Modular, extensible codebase**

## File Structure
```
pyguard trial/
├── main.py                  # (Optional) Launcher or utility
├── netscope/
│   ├── app.py               # Main PyQt5 desktop application (entry point)
│   ├── backend/
│   │   ├── capture.py       # Packet capture logic
│   │   ├── packet_sniffer.py# Scapy-based sniffer
│   │   ├── packets.py       # Packet data models/utilities
│   │   ├── view_packets.py  # CLI packet viewer
│   │   ├── requirements.txt # Backend dependencies
│   │   └── packets.db       # SQLite database (auto-created)
│   ├── ui/
│   │   ├── dashboard_tab.py # Dashboard UI
│   │   ├── live_capture_tab.py # Live capture UI
│   │   ├── filter_tab.py    # Filtering UI
│   │   ├── packet_details_tab.py # Packet details UI
│   │   ├── statistics_tab.py# Statistics UI
│   │   ├── ml_alerts_tab.py # ML alerts UI
│   │   ├── logs_tab.py      # Logs UI
│   │   ├── settings_tab.py  # Settings UI
│   │   ├── about_tab.py     # About tab UI
│   ├── resources/
│   │   └── icons/           # (Optional) App icons
│   └── __init__.py
├── netscope_ui.py           # (Legacy/alt UI, not main entry)
├── packets.db               # Main SQLite DB (auto-created)
├── p1.csv, p2.csv, p3.csv   # Example packet exports
├── tests/                   # (Optional) Test modules
└── README.md
```

## Quick Start
1. **Clone the repository:**
   ```powershell
   git clone https://github.com/MaitrikMakwana/PyGuard.git
   cd "pyguard trial"
   ```
2. **Set up a virtual environment (recommended):**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
3. **Install dependencies:**
   ```powershell
   pip install -r netscope/backend/requirements.txt
   pip install pyqt5 scapy pyqtgraph numpy
   ```
4. **Run the desktop app:**
   ```powershell
   python netscope/app.py
   ```
   The GUI will launch. Use the toolbar to start/stop capture, filter, export, and view ML alerts.

## ML-based Intrusion Detection
- The app extracts features from packets/flows and uses a trained ML model (scikit-learn compatible) for anomaly/threat detection.
- You can train your own model and integrate it (see backend code for details).

## Contributing
Contributions are welcome! Please open issues or pull requests. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License
MIT License
