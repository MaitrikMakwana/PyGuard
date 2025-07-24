import sys
import os
import json
import sqlite3
from collections import deque
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QTableWidget, QSizePolicy, 
                            QHBoxLayout, QLabel, QPushButton, QTableWidgetItem,
                            QHeaderView, QProgressBar, QFrame, QSplitter)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QIcon, QPixmap

# Add the backend directory to Python path
backend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'netscope', 'backend')
sys.path.insert(0, backend_dir)

try:
    from advanced_packet_viewer import AdvancedPacketViewer
    ENHANCED_VIEWING = True
except ImportError:
    ENHANCED_VIEWING = False

class LiveCaptureTab(QWidget):
    # Signal emitted when packet is selected for details
    packetSelected = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(32, 32, 32, 32)
        main_layout.setSpacing(24)

        # Action Bar (fixed at top)
        action_bar = QHBoxLayout()
        action_bar.setSpacing(16)
        live_icon = QLabel()
        live_icon.setPixmap(QPixmap(':/icons/live.png').scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        live_icon.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        action_bar.addWidget(live_icon)
        section_title = QLabel('Live Capture')
        section_title.setFont(QFont('Segoe UI', 22, QFont.Bold))
        section_title.setStyleSheet('color: #00BCD4;')
        action_bar.addWidget(section_title)
        action_bar.addStretch(1)
        self.refreshButton = QPushButton()
        self.refreshButton.setIcon(QIcon(':/icons/refresh.png'))
        self.refreshButton.setToolTip('Refresh Packets')
        self.refreshButton.setFixedSize(40, 40)
        self.refreshButton.setStyleSheet('''
            QPushButton {
                background: #1976D2;
                color: white;
                border-radius: 20px;
                font-size: 18px;
            }
            QPushButton:hover {
                background: #00BCD4;
            }
        ''')
        action_bar.addWidget(self.refreshButton)
        main_layout.addLayout(action_bar)

        # Status bar (below action bar)
        status_layout = QHBoxLayout()
        self.statusLabel = QLabel("📡 Live Packet Capture - Ready")
        self.statusLabel.setStyleSheet('''
            QLabel {
                color: #00BCD4;
                font-size: 20px;
                font-weight: bold;
                padding: 8px 0;
            }
        ''')
        self.packetCountLabel = QLabel("Packets: 0")
        self.packetCountLabel.setStyleSheet('''
            QLabel {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 12px;
                color: #4CAF50;
                font-size: 16px;
                padding: 8px 16px;
            }
        ''')
        status_layout.addWidget(self.statusLabel)
        status_layout.addStretch()
        status_layout.addWidget(self.packetCountLabel)
        main_layout.addLayout(status_layout)

        # Main content area: use a card for the table
        table_card = QFrame()
        table_card.setFrameShape(QFrame.StyledPanel)
        table_card.setFrameShadow(QFrame.Raised)
        table_card.setStyleSheet('''
            QFrame {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 24px;
                border: 1.5px solid rgba(255,255,255,0.08);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.18);
            }
        ''')
        table_layout = QVBoxLayout(table_card)
        table_layout.setContentsMargins(24, 24, 24, 24)
        table_layout.setSpacing(16)
        table_header = QLabel('Live Packets')
        table_header.setFont(QFont('Segoe UI', 18, QFont.Bold))
        table_header.setStyleSheet('color: #FF9800;')
        table_layout.addWidget(table_header)
        self.packetTable = QTableWidget(0, 7)
        self.packetTable.setObjectName('packetTable')
        self.packetTable.setHorizontalHeaderLabels([
            'ID', 'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Length', 'Info'
        ])
        header = self.packetTable.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.Stretch)
        self.packetTable.setAlternatingRowColors(True)
        self.packetTable.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.packetTable.setSelectionBehavior(QTableWidget.SelectRows)
        self.packetTable.setStyleSheet('''
            QTableWidget {
                background: transparent;
                border-radius: 16px;
                color: #E0E0E0;
                font-size: 16px;
                selection-background-color: #1976D2;
                selection-color: #FFFFFF;
                gridline-color: rgba(255,255,255,0.1);
            }
            QHeaderView::section {
                background: rgba(44, 44, 64, 0.8);
                color: #00BCD4;
                font-size: 16px;
                font-weight: bold;
                border: none;
                padding: 12px 8px;
                border-bottom: 2px solid #1976D2;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid rgba(255,255,255,0.05);
            }
            QTableWidget::item:hover {
                background: rgba(25, 118, 210, 0.15);
            }
            QTableWidget::item:selected {
                background: rgba(25, 118, 210, 0.3);
            }
        ''')
        table_layout.addWidget(self.packetTable)
        main_layout.addWidget(table_card)

        # Add Show All / Show Recent toggle at the bottom
        toggle_layout = QHBoxLayout()
        toggle_layout.addStretch(1)
        self.showAllButton = QPushButton('Show All Packets')
        self.showAllButton.setStyleSheet('''
            QPushButton {
                background: #1976D2;
                color: white;
                border-radius: 14px;
                padding: 8px 24px;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #00BCD4;
            }
        ''')
        self.showRecentButton = QPushButton('Show Recent 1000')
        self.showRecentButton.setStyleSheet('''
            QPushButton {
                background: #FF9800;
                color: white;
                border-radius: 14px;
                padding: 8px 24px;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #F57C00;
            }
        ''')
        toggle_layout.addWidget(self.showAllButton)
        toggle_layout.addWidget(self.showRecentButton)
        toggle_layout.addStretch(1)
        main_layout.addLayout(toggle_layout)
        self.showRecentButton.setVisible(False)  # Start in recent mode

        # Efficient buffer for new packets (deque with maxlen)
        self.packet_buffer = deque(maxlen=1000)  # Only keep the most recent 1000 packets
        self.last_packet_id = None
        self.showing_all = False

        # Connect signals
        self.refreshButton.clicked.connect(self.refresh_packets)
        self.packetTable.cellClicked.connect(self._on_packet_selected)
        self.showAllButton.clicked.connect(self._show_all_packets)
        self.showRecentButton.clicked.connect(self._show_recent_packets)

        # Timer for batching UI updates (every 2 seconds)
        self.ui_update_timer = QTimer()
        self.ui_update_timer.timeout.connect(self._update_ui_from_buffer)
        self.ui_update_timer.start(2000)  # 2 seconds

        # Track packet count
        self.last_packet_count = 0

    def refresh_packets(self):
        """Manually refresh packets from database (for refresh button)"""
        self._fetch_new_packets(force_all=True)
        self._update_ui_from_buffer()

    def _fetch_new_packets(self, force_all=False):
        """Fetch new packets from the database and buffer them."""
        try:
            conn = sqlite3.connect('packets.db')
            cursor = conn.cursor()
            if force_all or self.last_packet_id is None:
                cursor.execute('''
                    SELECT id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, details 
                    FROM packets 
                    ORDER BY id DESC 
                    LIMIT 1000
                ''')
            else:
                cursor.execute('''
                    SELECT id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, details 
                    FROM packets 
                    WHERE id > ?
                    ORDER BY id ASC
                ''', (self.last_packet_id,))
            rows = cursor.fetchall()
            if rows:
                for row in rows:
                    packet_id = row[0]
                    if self.last_packet_id is None or packet_id > self.last_packet_id:
                        self.packet_buffer.append(row)
                        self.last_packet_id = packet_id
            conn.close()
        except Exception as e:
            print(f"Error fetching packets: {e}")

    def _show_all_packets(self):
        self.showing_all = True
        self.showAllButton.setVisible(False)
        self.showRecentButton.setVisible(True)
        self._load_all_packets_to_table()

    def _show_recent_packets(self):
        self.showing_all = False
        self.showAllButton.setVisible(True)
        self.showRecentButton.setVisible(False)
        self._update_ui_from_buffer()

    def _load_all_packets_to_table(self):
        try:
            conn = sqlite3.connect('packets.db')
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, details 
                FROM packets 
                ORDER BY id DESC
            ''')
            rows = cursor.fetchall()
            conn.close()
            self.packetTable.setRowCount(len(rows))
            for row_idx, row in enumerate(rows):
                packet_id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, details_json = row
                details = {}
                try:
                    if details_json:
                        details = json.loads(details_json)
                except json.JSONDecodeError:
                    pass
                packet = {
                    'id': packet_id,
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': protocol,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'size': size,
                    **details
                }
                info = self._generate_packet_info(packet)
                columns = [
                    str(packet_id),
                    timestamp,
                    src_ip,
                    dst_ip,
                    protocol,
                    str(size),
                    info
                ]
                for col_idx, value in enumerate(columns):
                    item = QTableWidgetItem(str(value))
                    item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                    if col_idx == 4:
                        if protocol.upper() == 'TCP':
                            item.setBackground(Qt.darkBlue)
                        elif protocol.upper() == 'UDP':
                            item.setBackground(Qt.darkGreen)
                        elif protocol.upper() == 'ICMP':
                            item.setBackground(Qt.darkRed)
                        elif protocol.upper() == 'ARP':
                            item.setBackground(Qt.darkMagenta)
                        elif protocol.upper() == 'DNS':
                            item.setBackground(Qt.darkCyan)
                    if col_idx == 0:
                        item.setData(Qt.UserRole, packet)
                    self.packetTable.setItem(row_idx, col_idx, item)
            self.packetCountLabel.setText(f"Packets: {len(rows)}")
        except Exception as e:
            print(f"Error loading all packets: {e}")

    def _update_ui_from_buffer(self):
        if self.showing_all:
            return  # Don't update if showing all
        """Update the UI with buffered packets (called by timer)."""
        self._fetch_new_packets()
        # Only keep the most recent 1000 packets in the table
        packets_to_show = list(self.packet_buffer)[-1000:]
        self.packetTable.setRowCount(len(packets_to_show))
        for row_idx, row in enumerate(reversed(packets_to_show)):
            packet_id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, details_json = row
            details = {}
            try:
                if details_json:
                    details = json.loads(details_json)
            except json.JSONDecodeError:
                pass
            packet = {
                'id': packet_id,
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'src_port': src_port,
                'dst_port': dst_port,
                'size': size,
                **details
            }
            info = self._generate_packet_info(packet)
            columns = [
                str(packet_id),
                timestamp,
                src_ip,
                dst_ip,
                protocol,
                str(size),
                info
            ]
            for col_idx, value in enumerate(columns):
                item = QTableWidgetItem(str(value))
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                if col_idx == 4:
                    if protocol.upper() == 'TCP':
                        item.setBackground(Qt.darkBlue)
                    elif protocol.upper() == 'UDP':
                        item.setBackground(Qt.darkGreen)
                    elif protocol.upper() == 'ICMP':
                        item.setBackground(Qt.darkRed)
                    elif protocol.upper() == 'ARP':
                        item.setBackground(Qt.darkMagenta)
                    elif protocol.upper() == 'DNS':
                        item.setBackground(Qt.darkCyan)
                if col_idx == 0:
                    item.setData(Qt.UserRole, packet)
                self.packetTable.setItem(row_idx, col_idx, item)
        self.packetCountLabel.setText(f"Packets: {len(packets_to_show)}")
        self.last_packet_count = len(packets_to_show)

    def _generate_packet_info(self, packet):
        """Generate info string for packet (Wireshark-style)"""
        protocol = packet.get('protocol', '').upper()
        
        if protocol == 'TCP':
            src_port = packet.get('src_port', '')
            dst_port = packet.get('dst_port', '')
            flags = packet.get('tcp_flags', '')
            seq = packet.get('tcp_seq', '')
            ack = packet.get('tcp_ack', '')
            
            if flags:
                info = f"{src_port} → {dst_port} [{flags}]"
                if seq:
                    info += f" Seq={seq}"
                if ack:
                    info += f" Ack={ack}"
                return info
            else:
                return f"{src_port} → {dst_port}"
                
        elif protocol == 'UDP':
            src_port = packet.get('src_port', '')
            dst_port = packet.get('dst_port', '')
            length = packet.get('udp_len', packet.get('size', ''))
            return f"{src_port} → {dst_port} Len={length}"
            
        elif protocol == 'ICMP':
            icmp_type = packet.get('icmp_type', '')
            icmp_code = packet.get('icmp_code', '')
            icmp_id = packet.get('icmp_id', '')
            
            type_names = {
                0: 'Echo Reply',
                8: 'Echo Request',
                3: 'Dest Unreachable',
                11: 'Time Exceeded'
            }
            
            type_name = type_names.get(icmp_type, f'Type {icmp_type}')
            info = f"{type_name}"
            if icmp_code:
                info += f" Code={icmp_code}"
            if icmp_id:
                info += f" ID={icmp_id}"
            return info
            
        elif protocol == 'DNS':
            qname = packet.get('dns_qd', '')
            answer = packet.get('dns_an', '')
            qr = packet.get('dns_qr', 0)
            
            if qr == 0:  # Query
                return f"Standard query {qname}" if qname else "DNS Query"
            else:  # Response
                return f"Standard query response {answer}" if answer else "DNS Response"
                
        elif protocol == 'ARP':
            op = packet.get('arp_op', '')
            psrc = packet.get('arp_psrc', '')
            pdst = packet.get('arp_pdst', '')
            
            if op == 1:
                return f"Who has {pdst}? Tell {psrc}"
            elif op == 2:
                return f"{psrc} is at {packet.get('arp_hwsrc', '')}"
            else:
                return f"ARP Op={op}"
                
        elif protocol == 'HTTP':
            http_data = packet.get('http_data', '')
            if http_data:
                lines = http_data.split('\r\n')
                return lines[0] if lines else 'HTTP'
            return 'HTTP'
        
        return ""
    
    def _on_packet_selected(self, row, column):
        """Handle packet selection"""
        if row < self.packetTable.rowCount():
            # Get packet data from first column
            item = self.packetTable.item(row, 0)
            if item:
                packet_data = item.data(Qt.UserRole)
                if packet_data:
                    self.packetSelected.emit(packet_data)
    
    def set_capture_status(self, status):
        """Set capture status"""
        status_messages = {
            'starting': "📡 Live Packet Capture - Starting...",
            'active': "📡 Live Packet Capture - Active",
            'stopped': "📡 Live Packet Capture - Stopped",
            'error': "📡 Live Packet Capture - Error"
        }
        
        status_colors = {
            'starting': "#FF9800",
            'active': "#4CAF50", 
            'stopped': "#F44336",
            'error': "#F44336"
        }
        
        message = status_messages.get(status, "📡 Live Packet Capture - Unknown")
        color = status_colors.get(status, "#E0E0E0")
        
        self.statusLabel.setText(message)
        self.statusLabel.setStyleSheet(f'''
            QLabel {{
                color: {color};
                font-size: 20px;
                font-weight: bold;
                padding: 8px 0;
            }}
        ''')
    
    def clear_packets(self):
        """Clear all packets from table"""
        self.packetTable.setRowCount(0)
        self.packetCountLabel.setText("Packets: 0")
        self.last_packet_count = 0 
        self.packet_buffer.clear()
        self.last_packet_id = None 