# Enhanced Packet Filtering System - PyGuard

## Overview
This enhanced packet filtering system provides **Wireshark-like filtering capabilities** for the PyGuard network packet analyzer. It includes both **BPF (Berkeley Packet Filter)** for real-time capture filtering and **display filters** for post-capture analysis.

## 🚀 Key Features

### 1. **Enhanced BPF Capture Filtering**
- **Advanced validation** with security checks to prevent command injection
- **15+ filter presets** for common traffic types 
- **Comprehensive syntax help** with examples
- **Support for complex expressions** with proper operator precedence

### 2. **Wireshark-Style Display Filters**
- **Field-based filtering** using familiar Wireshark syntax (e.g., `ip.src`, `tcp.port`)
- **Multiple comparison operators**: `==`, `!=`, `>`, `<`, `>=`, `<=`, `contains`, `matches`
- **Logical combinations** with `and`, `or`, and parentheses
- **Protocol-specific field extraction** for TCP, UDP, ICMP, DNS, ARP

### 3. **Enhanced Database Schema**
- **Optimized table structure** with proper data types
- **Database indexes** for faster queries on common fields
- **Consistent schema** across all capture components
- **Better port handling** with integer storage

### 4. **Advanced Packet Viewer**
- **Summary and detailed views** for captured packets
- **Flexible sorting** by any field
- **Real-time filtering** with immediate results
- **Export capabilities** for further analysis

## 📁 New Files Added

### `advanced_packet_viewer.py`
Advanced packet analysis tool with Wireshark-style display filters:
```bash
# View all packets
python advanced_packet_viewer.py

# Filter by source IP
python advanced_packet_viewer.py -f "ip.src == 192.168.1.1"

# Complex filtering with sorting
python advanced_packet_viewer.py -f "tcp.port == 80" -s frame.len -r

# Show detailed packet information
python advanced_packet_viewer.py -f "protocol == DNS" -d
```

### `test_filtering.py`
Comprehensive test suite for all filtering components:
```bash
python test_filtering.py
```

### `demo_filtering.py`
Interactive demo showing filtering capabilities:
```bash
python demo_filtering.py
```

## 🔧 Enhanced Features in Existing Files

### `packet_sniffer.py`
**New Command Line Options:**
```bash
# Show comprehensive BPF help
python packet_sniffer.py --filter-help

# List all available presets
python packet_sniffer.py --common-filters

# Use a preset filter
python packet_sniffer.py --preset web_traffic

# Capture with custom filter
python packet_sniffer.py -f "tcp and (port 80 or port 443)"
```

**Enhanced Security:**
- ✅ Command injection prevention
- ✅ BPF syntax validation
- ✅ Shell operator detection
- ✅ Balanced parentheses checking

### Updated Database Schema
All database files now use consistent, optimized schema:
```sql
CREATE TABLE packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_port INTEGER,           -- Now stored as integer
    dst_port INTEGER,           -- Now stored as integer  
    size INTEGER NOT NULL,
    details TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Performance indexes
CREATE INDEX idx_timestamp ON packets(timestamp);
CREATE INDEX idx_src_ip ON packets(src_ip);
CREATE INDEX idx_dst_ip ON packets(dst_ip);
CREATE INDEX idx_protocol ON packets(protocol);
CREATE INDEX idx_src_port ON packets(src_port);
CREATE INDEX idx_dst_port ON packets(dst_port);
```

## 🎯 Filter Presets

### Available Presets (`--preset <name>`)
| Preset Name | Filter Expression | Description |
|-------------|------------------|-------------|
| `web_traffic` | `tcp and (port 80 or port 443 or port 8080)` | HTTP/HTTPS traffic |
| `dns_traffic` | `udp and port 53` | DNS queries/responses |
| `email_traffic` | `tcp and (port 25 or port 110 or port 143 or port 993 or port 995)` | Email protocols |
| `ssh_traffic` | `tcp and port 22` | SSH connections |
| `ftp_traffic` | `tcp and (port 20 or port 21)` | FTP traffic |
| `dhcp_traffic` | `udp and (port 67 or port 68)` | DHCP traffic |
| `icmp_traffic` | `icmp` | ICMP packets |
| `arp_traffic` | `arp` | ARP packets |
| `large_packets` | `len > 1000` | Large packets |
| `small_packets` | `len < 64` | Small packets |
| `tcp_syn` | `tcp and tcp[tcpflags] & tcp-syn != 0` | TCP SYN packets |
| `tcp_rst` | `tcp and tcp[tcpflags] & tcp-rst != 0` | TCP RST packets |
| `broadcast` | `ether broadcast or arp` | Broadcast traffic |
| `multicast` | `ether multicast` | Multicast traffic |
| `non_standard_ports` | `tcp and not (port 80 or port 443 or port 22 or port 25 or port 53)` | Unusual port usage |

## 🔍 Display Filter Examples

### Basic Filtering
```bash
# Traffic from specific IP
ip.src == 192.168.1.100

# Traffic to specific IP  
ip.dst == 8.8.8.8

# Specific protocol
protocol == TCP
```

### Port-Based Filtering
```bash
# HTTP traffic (any direction)
tcp.port == 80

# HTTPS outbound traffic
tcp.dstport == 443

# SSH traffic from specific source
ip.src == 192.168.1.100 and tcp.port == 22
```

### Size-Based Filtering
```bash
# Large packets
frame.len > 1000

# Standard Ethernet frames
frame.len >= 64 and frame.len <= 1518

# Jumbo frames
frame.len > 1500
```

### Protocol-Specific Filtering
```bash
# TCP flags
tcp.flags contains S     # SYN flag set
tcp.flags contains A     # ACK flag set

# ICMP types
icmp.type == 8          # Ping request
icmp.type == 0          # Ping reply

# DNS queries
dns.qry.name contains google
```

### Complex Logical Filtering
```bash
# Web traffic from internal network
ip.src == 192.168.1.0/24 and (tcp.port == 80 or tcp.port == 443)

# All traffic except ARP and ICMP
not (protocol == ARP or protocol == ICMP)

# Large TCP packets with specific flags
protocol == TCP and frame.len > 1000 and tcp.flags contains P
```

## 📊 Usage Examples

### Real-Time Capture with Filtering
```bash
# Capture only web traffic
python packet_sniffer.py --preset web_traffic

# Capture DNS traffic with custom database
python packet_sniffer.py -f "udp and port 53" --db-path dns_packets.db

# Capture large packets for analysis
python packet_sniffer.py --preset large_packets -c 100
```

### Post-Capture Analysis
```bash
# Analyze web traffic patterns
python advanced_packet_viewer.py -f "tcp.port == 80 or tcp.port == 443" -s frame.len

# Find DNS queries for specific domains
python advanced_packet_viewer.py -f "dns.qry.name contains google" -d

# Analyze traffic from specific host
python advanced_packet_viewer.py -f "ip.src == 192.168.1.100" -s timestamp -r
```

### Security Analysis
```bash
# Look for port scans (many different destination ports)
python advanced_packet_viewer.py -f "tcp.flags contains S" -s tcp.dstport

# Find large data transfers
python advanced_packet_viewer.py -f "frame.len > 1400" -s size -r

# Analyze ICMP traffic
python advanced_packet_viewer.py -f "protocol == ICMP" -d
```

## 🛡️ Security Features

### Input Validation
- **Command injection prevention** - Dangerous characters are blocked
- **Shell operator detection** - Prevents shell command execution
- **BPF syntax validation** - Ensures only valid filter expressions
- **Balanced bracket checking** - Prevents syntax errors

### Safe Filter Processing
- **Whitelist-based validation** - Only known BPF keywords allowed
- **Pattern matching** - Validates common filter patterns  
- **Sanitized execution** - Filters are safely passed to Scapy
- **Error handling** - Graceful failure for invalid filters

## 🚀 Performance Optimizations

### Database Improvements
- **Integer port storage** - Faster numeric comparisons
- **Comprehensive indexing** - Optimized queries on common fields
- **Batch operations** - Efficient bulk inserts during capture
- **Connection pooling** - Reduced database overhead

### Filter Processing
- **Compiled expressions** - Pre-processed filter functions
- **Lazy evaluation** - Short-circuit boolean operations
- **Type-aware comparisons** - Automatic type conversion
- **Caching** - Repeated filter expressions are cached

## 🧪 Testing

### Automated Test Suite
```bash
# Run all filtering tests
python test_filtering.py

# Expected output: All tests pass with ✓ marks
```

### Test Coverage
- ✅ BPF filter validation (valid/invalid cases)
- ✅ Display filter parsing and evaluation  
- ✅ Database schema consistency
- ✅ Security injection prevention
- ✅ Protocol-specific field extraction
- ✅ Complex logical expressions
- ✅ Performance with large datasets

## 📈 Improvements Made

### From Basic to Advanced Filtering

**Before:**
- Basic regex-based filter parsing
- Limited validation
- Inconsistent database schemas
- Simple string-based filtering

**After:**
- Comprehensive BPF validation with security checks
- Wireshark-style display filters with field mapping
- Optimized database schema with indexes
- Type-aware filtering with protocol-specific extraction
- 15+ filter presets for common use cases
- Advanced packet viewer with sorting and analysis
- Comprehensive test suite and documentation

## 🔄 Migration Guide

### For Existing Users
1. **Database compatibility** - New schema is backward compatible
2. **Command line** - All existing options still work
3. **Filter syntax** - Old filters continue to work
4. **New features** - Available through new command options

### Upgrading
```bash
# The system automatically handles database schema updates
# No manual migration required

# Test new features
python packet_sniffer.py --common-filters
python advanced_packet_viewer.py --filter-help
```

## 📚 Documentation

- **BPF Help**: `python packet_sniffer.py --filter-help`
- **Display Filter Help**: `python advanced_packet_viewer.py --filter-help`  
- **Available Presets**: `python packet_sniffer.py --common-filters`
- **Test Suite**: `python test_filtering.py`
- **Interactive Demo**: `python demo_filtering.py`

---

## 🎉 Conclusion

The enhanced filtering system now provides **professional-grade packet analysis capabilities** comparable to Wireshark, with:

✅ **Security-first design** preventing injection attacks  
✅ **Performance optimizations** for large-scale analysis  
✅ **User-friendly presets** for common use cases  
✅ **Comprehensive documentation** and testing  
✅ **Wireshark-compatible syntax** for familiar filtering  

The system is ready for production use and provides a solid foundation for advanced network traffic analysis.