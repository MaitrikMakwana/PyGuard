from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget, QTextEdit, QSizePolicy, QTableWidget, QTableWidgetItem, QTabWidget, QLabel, QFrame, QSplitter, QAbstractItemView
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
                font-size: 20px;
                font-weight: bold;
                padding: 12px;
            }
            QTreeWidget::item {
                font-size: 18px;
                font-weight: normal;
                padding: 8px 0;
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
        table = self.protocolTables.get(proto)
        if table is None:
            return
        table.setRowCount(0)
        for row, (field, value) in enumerate(fields_dict.items()):
            table.insertRow(row)
            
            # Create non-editable items
            field_item = QTableWidgetItem(str(field))
            field_item.setFlags(field_item.flags() & ~Qt.ItemIsEditable)
            
            value_item = QTableWidgetItem(str(value))
            value_item.setFlags(value_item.flags() & ~Qt.ItemIsEditable)
            
            table.setItem(row, 0, field_item)
            table.setItem(row, 1, value_item)

    def clear_details(self):
        self.protocolTree.clear()
        for table in self.protocolTables.values():
            table.setRowCount(0)
        self.hexDumpEdit.clear()

    def populate_protocol_tree(self, details):
        self.protocolTree.clear()
        protocol_fields = [
            ('Ethernet', ['eth_src', 'eth_dst', 'eth_type']),
            ('IP', ['ip_version', 'ip_ihl', 'ip_tos', 'ip_len', 'ip_id', 'ip_flags', 'ip_frag', 'ip_ttl', 'ip_proto', 'ip_chksum', 'ip_options']),
            ('TCP', ['tcp_seq', 'tcp_ack', 'tcp_dataofs', 'tcp_reserved', 'tcp_flags', 'tcp_window', 'tcp_chksum', 'tcp_urgptr', 'tcp_options']),
            ('UDP', ['udp_len', 'udp_chksum']),
            ('DNS', ['dns_id', 'dns_qr', 'dns_opcode', 'dns_aa', 'dns_tc', 'dns_rd', 'dns_ra', 'dns_z', 'dns_rcode', 'dns_qdcount', 'dns_ancount', 'dns_nscount', 'dns_arcount', 'dns_qd', 'dns_an']),
            ('ICMP', ['icmp_type', 'icmp_code', 'icmp_chksum', 'icmp_id', 'icmp_seq']),
            ('ARP', ['arp_hwtype', 'arp_ptype', 'arp_hwlen', 'arp_plen', 'arp_op', 'arp_hwsrc', 'arp_psrc', 'arp_hwdst', 'arp_pdst']),
            ('HTTP', ['http_data']),
        ]
        for proto, fields in protocol_fields:
            field_dict = {f: details[f] for f in fields if f in details}
            if field_dict:
                proto_item = self._make_protocol_tree_item(proto, field_dict)
                self.protocolTree.addTopLevelItem(proto_item)
        self.protocolTree.expandAll()

    def _make_protocol_tree_item(self, proto, field_dict):
        from PyQt5.QtWidgets import QTreeWidgetItem
        proto_item = QTreeWidgetItem([proto])
        proto_item.setFont(0, QFont('Segoe UI', 16, QFont.Bold))
        for field, value in field_dict.items():
            child = QTreeWidgetItem([f"{field.replace('_', ' ').title()}: {value}"])
            child.setFont(0, QFont('Segoe UI', 14))
            proto_item.addChild(child)
        return proto_item 