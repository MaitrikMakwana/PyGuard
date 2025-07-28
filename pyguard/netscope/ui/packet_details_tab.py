from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem, QTextEdit, QSizePolicy, QTableWidget, QTableWidgetItem, QTabWidget, QLabel, QFrame, QSplitter, QAbstractItemView
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QIcon, QPixmap

class PacketDetailsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 12, 16, 12)
        main_layout.setSpacing(8)

        # Action Bar (fixed at top)
        action_bar = QHBoxLayout()
        action_bar.setSpacing(12)
        details_icon = QLabel()
        details_icon.setPixmap(QPixmap(':/icons/details.png').scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        details_icon.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        action_bar.addWidget(details_icon)
        section_title = QLabel('Packet Details')
        section_title.setFont(QFont('Segoe UI', 22, QFont.Bold))
        section_title.setStyleSheet('color: #00BCD4;')
        action_bar.addWidget(section_title)
        action_bar.addStretch(1)
        main_layout.addLayout(action_bar)

        # QSplitter for vertical resizing between protocol details and hex dump
        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(8)

        # Protocol Details Card (full width)
        details_card = QFrame()
        details_card.setFrameShape(QFrame.StyledPanel)
        details_card.setFrameShadow(QFrame.Raised)
        details_card.setStyleSheet('''
            QFrame {
                background: rgba(44, 44, 64, 0.65);
                border-radius: 24px;
                border: 1.5px solid rgba(255,255,255,0.10);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.18);
            }
        ''')
        details_layout = QVBoxLayout(details_card)
        details_layout.setContentsMargins(12, 8, 12, 8)
        details_layout.setSpacing(8)
        details_header = QLabel('Protocol Layers & Fields')
        details_header.setFont(QFont('Segoe UI', 18, QFont.Bold))
        details_header.setStyleSheet('color: #FF9800;')
        details_header.setAlignment(Qt.AlignLeft)
        details_layout.addWidget(details_header)
        self.detailsTabWidget = QTabWidget()
        self.detailsTabWidget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.protocolTree = QTreeWidget()
        self.protocolTree.setObjectName('protocolTree')
        self.protocolTree.setHeaderLabel('Protocol Layers & Fields')
        # Completely disable editing to prevent users from modifying packet details
        self.protocolTree.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.protocolTree.setSelectionMode(QAbstractItemView.SingleSelection)
        self.protocolTree.setContextMenuPolicy(Qt.NoContextMenu)
        self.protocolTree.setStyleSheet('''
            QTreeWidget {
                background: transparent;
                border-radius: 18px;
                color: #E0E0E0;
                font-size: 14px;
                font-weight: bold;
                padding: 12px;
            }
            QTreeWidget::item {
                font-size: 12px;
                font-weight: normal;
                padding: 6px 0;
            }
        ''')
        self.detailsTabWidget.addTab(self.protocolTree, "Tree View")
        self.protocolTables = {}
        protocol_names = [
            'Ethernet', 'IP', 'TCP', 'UDP', 'DNS', 'ICMP', 'ARP', 'HTTP'
        ]
        for proto in protocol_names:
            table = QTableWidget(0, 2)
            table.setObjectName(f'{proto.lower()}Table')
            table.setHorizontalHeaderLabels(['Field', 'Value'])
            table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            # Completely disable editing to prevent users from modifying packet details
            table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            table.setSelectionMode(QAbstractItemView.SingleSelection)
            table.setContextMenuPolicy(Qt.NoContextMenu)
            table.setStyleSheet('''
                QTableWidget {
                    background: transparent;
                    border-radius: 12px;
                    color: #E0E0E0;
                    font-size: 18px;
                }
                QHeaderView::section {
                    background: transparent;
                    color: #B0B0B0;
                    font-size: 18px;
                    border: none;
                    padding: 12px 0;
                }
            ''')
            self.protocolTables[proto] = table
            self.detailsTabWidget.addTab(table, f"{proto} Header")
        details_layout.addWidget(self.detailsTabWidget)
        splitter.addWidget(details_card)

        # Hex Dump Card (full width, bottom)
        hex_card = QFrame()
        hex_card.setFrameShape(QFrame.StyledPanel)
        hex_card.setFrameShadow(QFrame.Raised)
        hex_card.setStyleSheet('''
            QFrame {
                background: rgba(44, 44, 64, 0.65);
                border-radius: 24px;
                border: 1.5px solid rgba(255,255,255,0.10);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.18);
            }
        ''')
        hex_layout = QVBoxLayout(hex_card)
        hex_layout.setContentsMargins(12, 8, 12, 8)
        hex_layout.setSpacing(8)
        hex_header = QLabel('Hex Dump')
        hex_header.setFont(QFont('Segoe UI', 18, QFont.Bold))
        hex_header.setStyleSheet('color: #FF9800;')
        hex_header.setAlignment(Qt.AlignLeft)
        hex_layout.addWidget(hex_header)
        self.hexDumpEdit = QTextEdit()
        self.hexDumpEdit.setObjectName('hexDumpEdit')
        self.hexDumpEdit.setReadOnly(True)
        self.hexDumpEdit.setContextMenuPolicy(Qt.NoContextMenu)
        self.hexDumpEdit.setStyleSheet('''
            QTextEdit {
                background: transparent;
                border-radius: 12px;
                color: #E0E0E0;
                font-size: 18px;
                font-family: 'Fira Mono', 'Consolas', 'monospace';
                padding: 12px;
            }
        ''')
        self.hexDumpEdit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        hex_layout.addWidget(self.hexDumpEdit)
        splitter.addWidget(hex_card)
        splitter.setSizes([600, 200])

        main_layout.addWidget(splitter)

    def populate_protocol_table(self, proto, fields_dict):
        """
        Populate a protocol-specific table with field data
        
        Args:
            proto: Protocol name (Ethernet, IP, TCP, etc.)
            fields_dict: Dictionary of field names and values
        """
        table = self.protocolTables.get(proto)
        if table is None:
            return
            
        # Clear the table
        table.setRowCount(0)
        
        # Sort fields for consistent display
        sorted_fields = sorted(fields_dict.items())
        
        # Track the current row
        current_row = 0
        
        # Add each field to the table
        for field, value in sorted_fields:
            # Format field name for better readability
            field_name = field.replace('_', ' ').title()
            
            # Handle different value types
            if isinstance(value, dict):
                # Add the dictionary field as a parent row
                table.insertRow(current_row)
                field_item = QTableWidgetItem(field_name)
                field_item.setFlags(field_item.flags() & ~Qt.ItemIsEditable)
                field_item.setFont(QFont('Segoe UI', 12, QFont.Bold))
                table.setItem(current_row, 0, field_item)
                table.setItem(current_row, 1, QTableWidgetItem(""))
                current_row += 1
                
                # Add each key-value pair in the dictionary
                for k, v in value.items():
                    table.insertRow(current_row)
                    sub_field_item = QTableWidgetItem(f"  • {k}")
                    sub_field_item.setFlags(sub_field_item.flags() & ~Qt.ItemIsEditable)
                    
                    sub_value_item = QTableWidgetItem(str(v))
                    sub_value_item.setFlags(sub_value_item.flags() & ~Qt.ItemIsEditable)
                    
                    table.setItem(current_row, 0, sub_field_item)
                    table.setItem(current_row, 1, sub_value_item)
                    current_row += 1
                    
            elif isinstance(value, list) and len(value) > 0:
                # Add the list field as a parent row
                table.insertRow(current_row)
                field_item = QTableWidgetItem(field_name)
                field_item.setFlags(field_item.flags() & ~Qt.ItemIsEditable)
                field_item.setFont(QFont('Segoe UI', 12, QFont.Bold))
                table.setItem(current_row, 0, field_item)
                table.setItem(current_row, 1, QTableWidgetItem(f"{len(value)} items"))
                current_row += 1
                
                # Add each item in the list
                for i, item in enumerate(value):
                    table.insertRow(current_row)
                    sub_field_item = QTableWidgetItem(f"  • Item {i+1}")
                    sub_field_item.setFlags(sub_field_item.flags() & ~Qt.ItemIsEditable)
                    
                    sub_value_item = QTableWidgetItem(str(item))
                    sub_value_item.setFlags(sub_value_item.flags() & ~Qt.ItemIsEditable)
                    
                    table.setItem(current_row, 0, sub_field_item)
                    table.setItem(current_row, 1, sub_value_item)
                    current_row += 1
            else:
                # Regular field
                table.insertRow(current_row)
                
                # Create non-editable items
                field_item = QTableWidgetItem(field_name)
                field_item.setFlags(field_item.flags() & ~Qt.ItemIsEditable)
                
                # Format value based on field type
                if field.startswith('tcp_flags_') or field.startswith('Flag '):
                    # Highlight TCP flags
                    value_str = str(value)
                    if value_str == '1':
                        value_str = '✓ (Set)'
                    elif value_str == '0':
                        value_str = '✗ (Not Set)'
                elif field.endswith('_type') or field.endswith('_code'):
                    # Add numeric and descriptive value
                    value_str = str(value)
                else:
                    value_str = str(value)
                
                value_item = QTableWidgetItem(value_str)
                value_item.setFlags(value_item.flags() & ~Qt.ItemIsEditable)
                
                table.setItem(current_row, 0, field_item)
                table.setItem(current_row, 1, value_item)
                current_row += 1
                
        # Resize columns to content
        table.resizeColumnsToContents()
        table.resizeRowsToContents()

    def clear_details(self):
        """Clear all details from the UI"""
        self.protocolTree.clear()
        for table in self.protocolTables.values():
            table.setRowCount(0)
        self.hexDumpEdit.clear()

    def populate_protocol_tree(self, details):
        """
        Populate the protocol tree view with hierarchical packet data
        
        Args:
            details: Dictionary containing packet data
        """
        self.protocolTree.clear()
        
        # Create a root item for basic packet information
        basic_item = QTreeWidgetItem(['Packet Information'])
        basic_item.setFont(0, QFont('Segoe UI', 12, QFont.Bold))
        self.protocolTree.addTopLevelItem(basic_item)
        
        # Add basic packet information
        basic_fields = ['timestamp', 'protocol', 'packet_length', 'payload_length']
        for field in basic_fields:
            if field in details:
                child = QTreeWidgetItem([f"{field.replace('_', ' ').title()}: {details[field]}"])
                child.setFont(0, QFont('Segoe UI', 10))
                basic_item.addChild(child)
        
        # Determine protocol type for transport layer filtering
        protocol_type = details.get('protocol', '').upper()
        ip_proto = details.get('ip_proto', None)
        ip_proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        proto_detected = None
        if protocol_type in ['TCP', 'UDP']:
            proto_detected = protocol_type
        elif isinstance(ip_proto, int) and ip_proto in ip_proto_map:
            proto_detected = ip_proto_map[ip_proto]

        # Define protocol fields for each protocol
        protocol_fields = [
            ('Ethernet', ['eth_src', 'eth_dst', 'eth_type']),
            ('IP', ['src_ip', 'dst_ip', 'ip_version', 'ip_ihl', 'ip_tos', 'ip_len', 'ip_id', 'ip_flags', 'ip_frag', 'ip_ttl', 'ip_proto', 'ip_chksum', 'ip_options']),
            # Only add TCP or UDP, not both
            ('TCP', ['src_port', 'dst_port', 'tcp_seq', 'tcp_ack', 'tcp_dataofs', 'tcp_reserved', 'tcp_flags', 'tcp_flags_raw', 'tcp_window', 'tcp_chksum', 'tcp_urgptr', 'tcp_options']) if proto_detected == 'TCP' else None,
            ('UDP', ['src_port', 'dst_port', 'udp_len', 'udp_chksum']) if proto_detected == 'UDP' else None,
            ('DNS', ['dns_id', 'dns_qr', 'dns_opcode', 'dns_aa', 'dns_tc', 'dns_rd', 'dns_ra', 'dns_z', 'dns_rcode', 'dns_qdcount', 'dns_ancount', 'dns_nscount', 'dns_arcount', 'dns_qd', 'dns_an', 'dns_qname', 'dns_qtype', 'dns_qclass', 'dns_type', 'dns_an_name', 'dns_an_type', 'dns_an_rdata', 'dns_an_ttl']),
            ('ICMP', ['icmp_type', 'icmp_code', 'icmp_chksum', 'icmp_id', 'icmp_seq', 'icmp_type_name']),
            ('ARP', ['arp_hwtype', 'arp_ptype', 'arp_hwlen', 'arp_plen', 'arp_op', 'arp_op_name', 'arp_hwsrc', 'arp_psrc', 'arp_hwdst', 'arp_pdst']),
            ('HTTP', ['http_data', 'http_method', 'http_uri', 'http_version', 'http_headers']),
        ]
        # Remove None entries (i.e., the transport protocol not in use)
        protocol_fields = [pf for pf in protocol_fields if pf is not None]

        # Add protocol-specific fields to the tree view
        for proto, fields in protocol_fields:
            field_dict = {f: details[f] for f in fields if f in details}
            # Only add protocols that have data
            if field_dict:
                proto_item = self._make_protocol_tree_item(proto, field_dict)
                self.protocolTree.addTopLevelItem(proto_item)
        
        # Special handling for TCP flags
        if 'tcp_flags' in details and isinstance(details['tcp_flags'], dict):
            tcp_flags = details['tcp_flags']
            tcp_item = None
            
            # Find existing TCP item or create a new one
            for i in range(self.protocolTree.topLevelItemCount()):
                if self.protocolTree.topLevelItem(i).text(0) == 'TCP':
                    tcp_item = self.protocolTree.topLevelItem(i)
                    break
            
            if tcp_item is None and any(tcp_flags.values()):
                tcp_item = QTreeWidgetItem(['TCP'])
                tcp_item.setFont(0, QFont('Segoe UI', 12, QFont.Bold))
                self.protocolTree.addTopLevelItem(tcp_item)
            
            if tcp_item is not None:
                flags_item = QTreeWidgetItem(['TCP Flags'])
                flags_item.setFont(0, QFont('Segoe UI', 11))
                tcp_item.addChild(flags_item)
                
                for flag, value in tcp_flags.items():
                    flag_item = QTreeWidgetItem([f"{flag}: {value}"])
                    flag_item.setFont(0, QFont('Segoe UI', 10))
                    flags_item.addChild(flag_item)
        
        # Expand all items for better visibility
        self.protocolTree.expandAll()

    def _make_protocol_tree_item(self, proto, field_dict):
        proto_item = QTreeWidgetItem([proto])
        proto_item.setFont(0, QFont('Segoe UI', 12, QFont.Bold))
        
        # Sort fields for better organization
        sorted_fields = sorted(field_dict.items())
        
        for field, value in sorted_fields:
            # Format field name for better readability
            field_name = field.replace('_', ' ').title()
            
            # Handle special cases for better display
            if isinstance(value, dict):
                # Create a parent item for the dictionary
                dict_item = QTreeWidgetItem([field_name])
                dict_item.setFont(0, QFont('Segoe UI', 11))
                proto_item.addChild(dict_item)
                
                # Add each key-value pair as a child
                for k, v in value.items():
                    sub_child = QTreeWidgetItem([f"{k}: {v}"])
                    sub_child.setFont(0, QFont('Segoe UI', 10))
                    dict_item.addChild(sub_child)
            elif isinstance(value, list) and len(value) > 0:
                # Create a parent item for the list
                list_item = QTreeWidgetItem([field_name])
                list_item.setFont(0, QFont('Segoe UI', 11))
                proto_item.addChild(list_item)
                
                # Add each list item as a child
                for i, item in enumerate(value):
                    sub_child = QTreeWidgetItem([f"Item {i}: {item}"])
                    sub_child.setFont(0, QFont('Segoe UI', 10))
                    list_item.addChild(sub_child)
            else:
                # Regular field
                child = QTreeWidgetItem([f"{field_name}: {value}"])
                child.setFont(0, QFont('Segoe UI', 10))
                proto_item.addChild(child)
                
        return proto_item
        
    def show_packet_details(self, details):
        """
        Show packet details in both tree view and protocol-specific tabs
        
        Args:
            details: Dictionary containing packet data
        """
        # Clear previous details
        self.clear_details()
        
        # Populate tree view with all protocol information
        self.populate_protocol_tree(details)
        
        # Define protocol fields for each protocol tab with comprehensive field lists
        protocol_fields = {
            'Ethernet': [
                'eth_src', 'eth_dst', 'eth_type'
            ],
            'IP': [
                'src_ip', 'dst_ip', 'ip_version', 'ip_ihl', 'ip_tos', 'ip_len', 
                'ip_id', 'ip_flags', 'ip_frag', 'ip_ttl', 'ip_proto', 'ip_chksum', 
                'ip_options'
            ],
            'TCP': [
                'src_port', 'dst_port', 'tcp_seq', 'tcp_ack', 'tcp_dataofs', 
                'tcp_reserved', 'tcp_flags_raw', 'tcp_window', 'tcp_chksum', 
                'tcp_urgptr', 'tcp_options'
            ],
            'UDP': [
                'src_port', 'dst_port', 'udp_len', 'udp_chksum'
            ],
            'DNS': [
                'dns_id', 'dns_qr', 'dns_opcode', 'dns_aa', 'dns_tc', 'dns_rd', 
                'dns_ra', 'dns_z', 'dns_rcode', 'dns_qdcount', 'dns_ancount', 
                'dns_nscount', 'dns_arcount', 'dns_qd', 'dns_an', 'dns_qname', 
                'dns_qtype', 'dns_qclass', 'dns_type', 'dns_an_name', 'dns_an_type', 
                'dns_an_rdata', 'dns_an_ttl'
            ],
            'ICMP': [
                'icmp_type', 'icmp_code', 'icmp_chksum', 'icmp_id', 'icmp_seq', 
                'icmp_type_name'
            ],
            'ARP': [
                'arp_hwtype', 'arp_ptype', 'arp_hwlen', 'arp_plen', 'arp_op', 
                'arp_op_name', 'arp_hwsrc', 'arp_psrc', 'arp_hwdst', 'arp_pdst'
            ],
            'HTTP': [
                'http_data', 'http_method', 'http_uri', 'http_version', 'http_headers'
            ]
        }
        
        # Add basic packet information to each protocol tab
        basic_fields = [
            'timestamp', 'protocol', 'packet_length', 'payload_length'
        ]
        
        # More efficient protocol detection using prefix checks
        # This is faster than checking each field individually
        protocol_prefixes = {
            'Ethernet': 'eth_',
            'IP': 'ip_',
            'TCP': 'tcp_',
            'UDP': 'udp_',
            'DNS': 'dns_',
            'ICMP': 'icmp_',
            'ARP': 'arp_',
            'HTTP': 'http_'
        }
        
        # Determine active protocols strictly based on protocol field
        active_protocols = []
        protocol_type = details.get('protocol', '').upper()
        ip_proto = details.get('ip_proto', None)
        # Map IP protocol numbers to names
        ip_proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        # Always add Ethernet if any data
        if details:
            active_protocols.append('Ethernet')
        # Add IP if present
        if 'src_ip' in details or 'dst_ip' in details or any(k.startswith('ip_') for k in details.keys()):
            active_protocols.append('IP')
        # Add ARP if ARP fields present
        if any(k.startswith('arp_') for k in details.keys()):
            active_protocols.append('ARP')
        # Add ICMP if ICMP fields present or protocol indicates ICMP
        if (ip_proto == 1 or protocol_type == 'ICMP' or any(k.startswith('icmp_') for k in details.keys())):
            active_protocols.append('ICMP')
        # Add TCP or UDP strictly based on protocol
        proto_detected = None
        if protocol_type in ['TCP', 'UDP']:
            proto_detected = protocol_type
        elif isinstance(ip_proto, int) and ip_proto in ip_proto_map:
            proto_detected = ip_proto_map[ip_proto]
        if proto_detected == 'TCP':
            active_protocols.append('TCP')
        elif proto_detected == 'UDP':
            active_protocols.append('UDP')
        # DNS and HTTP (application layer) only if protocol matches
        if proto_detected == 'UDP' and any(k.startswith('dns_') for k in details.keys()):
            active_protocols.append('DNS')
        if proto_detected == 'TCP' and any(k.startswith('http_') for k in details.keys()):
            active_protocols.append('HTTP')
        # Sort protocols in the correct network stack order
        protocol_order = ['Ethernet', 'IP', 'ARP', 'ICMP', 'TCP', 'UDP', 'DNS', 'HTTP']
        active_protocols = sorted(active_protocols, key=lambda x: protocol_order.index(x) if x in protocol_order else 999)
            
        # Clear all protocol tables first
        for proto in self.protocolTables.keys():
            self.protocolTables[proto].setRowCount(0)
            
        # Populate only the relevant protocol tabs
        first_present = None
        for proto in active_protocols:
            fields = protocol_fields.get(proto, [])
            
            # Start with basic fields that should be in every tab
            field_dict = {}
            for field in basic_fields:
                if field in details:
                    field_dict[f'Packet {field}'] = details[field]
            
            # Add protocol-specific fields
            protocol_specific_fields_found = False
            for field in fields:
                if field in details:
                    field_dict[field] = details[field]
                    protocol_specific_fields_found = True
            
            # Skip this protocol if no protocol-specific fields were found
            # (except for Ethernet which we always want to show)
            if not protocol_specific_fields_found and proto != 'Ethernet':
                continue
            
            # Special handling for TCP flags
            if proto == 'TCP' and 'tcp_flags' in details and isinstance(details['tcp_flags'], dict):
                field_dict['TCP Flags'] = details['tcp_flags']
            
            # Special handling for HTTP headers
            if proto == 'HTTP' and 'http_headers' in details and isinstance(details['http_headers'], list):
                for i, header in enumerate(details['http_headers']):
                    field_dict[f'Header {i+1}'] = header
            
            # Populate the table
            self.populate_protocol_table(proto, field_dict)
            
            # Track the first protocol with data (prioritize the lowest layer)
            if field_dict and (first_present is None or 
                              protocol_order.index(proto) < protocol_order.index(first_present)):
                first_present = proto
                
        # Show hex dump if available
        hex_dump = details.get('raw', '')
        if hex_dump:
            try:
                hex_bytes = bytes.fromhex(hex_dump)
                hex_lines = []
                for i in range(0, len(hex_bytes), 16):
                    chunk = hex_bytes[i:i+16]
                    hex_part = ' '.join(f'{b:02X}' for b in chunk)
                    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                    hex_lines.append(f'{i:04X}  {hex_part:<48}  {ascii_part}')
                self.hexDumpEdit.setPlainText('\n'.join(hex_lines))
            except Exception:
                self.hexDumpEdit.setPlainText(hex_dump)
        else:
            self.hexDumpEdit.setPlainText('')
            
        # Determine the most relevant tab to show first
        if first_present:
            # Get the index of the tab for this protocol
            try:
                idx = list(self.protocolTables.keys()).index(first_present) + 1  # +1 for tree view tab
                
                # Only switch if the tab has content
                if self.protocolTables[first_present].rowCount() > 0:
                    self.detailsTabWidget.setCurrentIndex(idx)
                else:
                    # If the tab is empty, default to tree view
                    self.detailsTabWidget.setCurrentIndex(0)
            except (ValueError, IndexError):
                # If there's an error finding the tab, default to tree view
                self.detailsTabWidget.setCurrentIndex(0)
        else:
            # If no protocol was identified, default to tree view
            self.detailsTabWidget.setCurrentIndex(0)
            
        # Hide empty tabs
        for i, proto in enumerate(self.protocolTables.keys()):
            tab_idx = i + 1  # +1 for tree view tab
            if self.protocolTables[proto].rowCount() == 0:
                # If this tab is currently selected and empty, switch to tree view
                if self.detailsTabWidget.currentIndex() == tab_idx:
                    self.detailsTabWidget.setCurrentIndex(0)
                    
        # Make sure the selected tab has content
        current_idx = self.detailsTabWidget.currentIndex()
        if current_idx > 0:  # Not tree view
            proto = list(self.protocolTables.keys())[current_idx - 1]
            if self.protocolTables[proto].rowCount() == 0:
                # If empty, switch to tree view
                self.detailsTabWidget.setCurrentIndex(0)