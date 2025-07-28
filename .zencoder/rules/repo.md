---
description: Repository Information Overview
alwaysApply: true
---

# PyGuard Information

## Summary
PyGuard is a Python desktop network analyzer and ML-based host intrusion detection system. It provides real-time packet capture, storage, analysis, and visualization capabilities through a PyQt5 GUI interface. The application uses Scapy for network packet sniffing and SQLite for local storage.

## Structure
- **pyguard/**: Main application directory
  - **netscope/**: Core application module
    - **app.py**: Main PyQt5 desktop application (entry point)
    - **backend/**: Packet capture and processing logic
    - **ui/**: PyQt5 UI components
  - **tests/**: Test modules

## Language & Runtime
**Language**: Python 3.8+
**Build System**: pip
**Package Manager**: pip

## Dependencies
**Main Dependencies**:
- scapy: Network packet capture and analysis
- PyQt5: Desktop GUI framework
- sqlite3: Local database storage (built-in)
- pyqtgraph: Graphing and visualization
- numpy: Numerical operations
- scikit-learn: Machine learning for intrusion detection

**Development Dependencies**:
- pytest (implied for testing)

## Build & Installation
```bash
# Set up virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r netscope/backend/requirements.txt
pip install pyqt5 scapy pyqtgraph numpy scikit-learn

# Run the application
python netscope/app.py
```

## Protocol Headers Implementation

### Packet Capture & Processing
The application captures and processes network packets using Scapy, extracting detailed information from various protocol headers:

**Ethernet Header Fields**:
- eth_src: Source MAC address
- eth_dst: Destination MAC address
- eth_type: EtherType value

**IP Header Fields**:
- ip_version: IP version (4/6)
- ip_ihl: Internet Header Length
- ip_tos: Type of Service
- ip_len: Total Length
- ip_id: Identification
- ip_flags: Flags
- ip_frag: Fragment Offset
- ip_ttl: Time to Live
- ip_proto: Protocol
- ip_chksum: Header Checksum
- ip_options: IP Options

**TCP Header Fields**:
- tcp_seq: Sequence Number
- tcp_ack: Acknowledgment Number
- tcp_dataofs: Data Offset
- tcp_reserved: Reserved bits
- tcp_flags: Control Flags (SYN, ACK, FIN, RST, PSH, URG)
- tcp_window: Window Size
- tcp_chksum: Checksum
- tcp_urgptr: Urgent Pointer
- tcp_options: TCP Options

**UDP Header Fields**:
- udp_len: Length
- udp_chksum: Checksum

**DNS Header Fields**:
- dns_id: Transaction ID
- dns_qr: Query/Response flag
- dns_opcode: Operation Code
- dns_aa: Authoritative Answer
- dns_tc: Truncation
- dns_rd: Recursion Desired
- dns_ra: Recursion Available
- dns_z: Reserved
- dns_rcode: Response Code
- dns_qdcount: Question Count
- dns_ancount: Answer Count
- dns_nscount: Authority Count
- dns_arcount: Additional Count
- dns_qname: Query Name

**ICMP Header Fields**:
- icmp_type: Type
- icmp_code: Code
- icmp_chksum: Checksum
- icmp_id: Identifier
- icmp_seq: Sequence Number

**ARP Header Fields**:
- arp_hwtype: Hardware Type
- arp_ptype: Protocol Type
- arp_hwlen: Hardware Address Length
- arp_plen: Protocol Address Length
- arp_op: Operation
- arp_hwsrc: Sender Hardware Address
- arp_psrc: Sender Protocol Address
- arp_hwdst: Target Hardware Address
- arp_pdst: Target Protocol Address

**HTTP Header Fields**:
- http_data: HTTP payload data
- http_method: HTTP method (GET, POST, etc.)
- http_uri: Request URI
- http_version: HTTP version
- http_headers: HTTP headers

### UI Display
The application displays protocol information in two ways:
1. **Tree View**: Hierarchical display of all protocol layers and fields
2. **Protocol-specific Tabs**: Dedicated tabs for each protocol (Ethernet, IP, TCP, UDP, DNS, ICMP, ARP, HTTP)

All protocol fields are displayed in both the tree view and their respective protocol tabs, providing comprehensive packet inspection capabilities.

## Features
The enhanced packet capture module provides:

1. **Interface Selection**:
   - Supports multiple network interfaces
   - Interface auto-detection

2. **Packet Capture**:
   - Real-time capture using Scapy's sniff() function
   - Configurable packet count and duration limits
   - BPF filter support for targeted capture

3. **Field Extraction**:
   - Timestamp (packet arrival time)
   - Source/Destination IP addresses
   - Source/Destination ports
   - Protocol identification
   - Packet and payload length
   - TCP flags (SYN, ACK, FIN, RST, PSH, URG)

4. **Storage Format**:
   - In-memory buffering with periodic disk writes
   - SQLite database storage with optimized schema
   - JSON and CSV export capabilities
   - File rotation by size or time interval

5. **Configuration**:
   - Interface selection
   - BPF filter expressions
   - Output directory and file naming
   - Rotation settings
   - Sampling rate control

6. **Error Handling**:
   - Comprehensive logging
   - Permission and interface error handling
   - Dropped packet tracking

7. **Performance Optimizations**:
   - Asynchronous I/O for non-blocking disk writes
   - Batch database operations
   - Optional packet sampling

## Testing
**Framework**: pytest (implied)
**Test Location**: pyguard/tests/
**Run Command**:
```bash
pytest
```