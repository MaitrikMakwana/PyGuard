from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame, QTableWidget, QTableWidgetItem, QSizePolicy
from PyQt5.QtCore import Qt
import pyqtgraph as pg
from PyQt5.QtGui import QFont, QIcon, QPixmap

class StatisticsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(32, 32, 32, 32)
        main_layout.setSpacing(24)

        # Action Bar (fixed at top)
        action_bar = QHBoxLayout()
        action_bar.setSpacing(16)
        stats_icon = QLabel()
        stats_icon.setPixmap(QPixmap(':/icons/statistics.png').scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        stats_icon.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        action_bar.addWidget(stats_icon)
        section_title = QLabel('Statistics')
        section_title.setFont(QFont('Segoe UI', 22, QFont.Bold))
        section_title.setStyleSheet('color: #00BCD4;')
        action_bar.addWidget(section_title)
        action_bar.addStretch(1)
        self.refreshButton = QPushButton()
        self.refreshButton.setIcon(QIcon(':/icons/refresh.png'))
        self.refreshButton.setToolTip('Refresh Statistics')
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

        # Main statistics layout: 3 tables in a vertical splitter
        from PyQt5.QtWidgets import QSplitter
        main_splitter = QSplitter(Qt.Vertical)

        # Protocol Legend
        legend_card = QFrame()
        legend_card.setFrameShape(QFrame.StyledPanel)
        legend_card.setFrameShadow(QFrame.Raised)
        legend_card.setStyleSheet('''
            QFrame {
                background: rgba(44,44,64,0.45);
                border-radius: 18px;
                border: 1.5px solid rgba(255,255,255,0.10);
            }
        ''')
        legend_row = QHBoxLayout(legend_card)
        legend_row.setContentsMargins(18, 8, 18, 8)
        protocol_colors = [
            ('TCP', '#1976D2'),
            ('UDP', '#00BCD4'),
            ('ICMP', '#43A047'),
            ('ARP', '#FBC02D'),
            ('DNS', '#8E24AA'),
            ('HTTP', '#E64A19'),
            ('OTHER', '#757575'),
        ]
        for proto, color in protocol_colors:
            color_box = QFrame()
            color_box.setFixedSize(18, 18)
            color_box.setStyleSheet(f'background: {color}; border-radius: 4px; border: 1px solid #222;')
            label = QLabel(proto)
            label.setStyleSheet('color: #E0E0E0; font-size: 13px; margin-left: 6px; margin-right: 18px;')
            legend_item = QHBoxLayout()
            legend_item.setSpacing(0)
            legend_item.addWidget(color_box)
            legend_item.addWidget(label)
            legend_item.setAlignment(Qt.AlignLeft)
            legend_widget = QWidget()
            legend_widget.setLayout(legend_item)
            legend_row.addWidget(legend_widget)
        legend_row.addStretch(1)
        main_layout.addWidget(legend_card)

        # Top Table: Top Talkers
        talkers_card = QFrame()
        talkers_card.setFrameShape(QFrame.StyledPanel)
        talkers_card.setFrameShadow(QFrame.Raised)
        talkers_card.setStyleSheet('''
            QFrame {
                background: rgba(44,44,64,0.65);
                border-radius: 18px;
                border: 1.5px solid rgba(0,188,212,0.18);
                margin-bottom: 8px;
            }
        ''')
        talkers_layout = QVBoxLayout(talkers_card)
        talkers_layout.setContentsMargins(18, 18, 18, 18)
        talkers_layout.setSpacing(8)
        talkers_label = QLabel('Top Talkers (IP)')
        talkers_label.setFont(QFont('Segoe UI', 16, QFont.Bold))
        talkers_label.setStyleSheet('color: #00BCD4;')
        talkers_layout.addWidget(talkers_label)
        self.topTalkersTable = QTableWidget(0, 3)
        self.topTalkersTable.setHorizontalHeaderLabels(['IP', 'Packets', 'Bytes'])
        self.topTalkersTable.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.topTalkersTable.setMinimumHeight(120)
        self.topTalkersTable.setStyleSheet('background: transparent; border-radius: 12px; color: #E0E0E0; font-size: 15px;')
        talkers_layout.addWidget(self.topTalkersTable)
        main_splitter.addWidget(talkers_card)

        # Middle Table: Top Ports
        ports_card = QFrame()
        ports_card.setFrameShape(QFrame.StyledPanel)
        ports_card.setFrameShadow(QFrame.Raised)
        ports_card.setStyleSheet('''
            QFrame {
                background: rgba(44,44,64,0.65);
                border-radius: 18px;
                border: 1.5px solid rgba(76,175,80,0.18);
                margin-bottom: 8px;
            }
        ''')
        ports_layout = QVBoxLayout(ports_card)
        ports_layout.setContentsMargins(18, 18, 18, 18)
        ports_layout.setSpacing(8)
        ports_label = QLabel('Top Ports')
        ports_label.setFont(QFont('Segoe UI', 16, QFont.Bold))
        ports_label.setStyleSheet('color: #4CAF50;')
        ports_layout.addWidget(ports_label)
        self.topPortsTable = QTableWidget(0, 3)
        self.topPortsTable.setHorizontalHeaderLabels(['Port', 'Packets', 'Bytes'])
        self.topPortsTable.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.topPortsTable.setMinimumHeight(120)
        self.topPortsTable.setStyleSheet('background: transparent; border-radius: 12px; color: #E0E0E0; font-size: 15px;')
        ports_layout.addWidget(self.topPortsTable)
        main_splitter.addWidget(ports_card)

        # Bottom Table: Protocol Usage
        proto_card = QFrame()
        proto_card.setFrameShape(QFrame.StyledPanel)
        proto_card.setFrameShadow(QFrame.Raised)
        proto_card.setStyleSheet('''
            QFrame {
                background: rgba(44,44,64,0.65);
                border-radius: 18px;
                border: 1.5px solid rgba(255,152,0,0.18);
            }
        ''')
        proto_layout = QVBoxLayout(proto_card)
        proto_layout.setContentsMargins(18, 18, 18, 18)
        proto_layout.setSpacing(8)
        proto_label = QLabel('Protocol Usage')
        proto_label.setFont(QFont('Segoe UI', 16, QFont.Bold))
        proto_label.setStyleSheet('color: #FF9800;')
        proto_layout.addWidget(proto_label)
        self.protocolUsageTable = QTableWidget(0, 4)
        self.protocolUsageTable.setHorizontalHeaderLabels(['Protocol', 'Packets', 'Bytes', 'Percent'])
        self.protocolUsageTable.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.protocolUsageTable.setMinimumHeight(120)
        self.protocolUsageTable.setStyleSheet('background: transparent; border-radius: 12px; color: #E0E0E0; font-size: 15px;')
        proto_layout.addWidget(self.protocolUsageTable)
        main_splitter.addWidget(proto_card)

        # Add the splitter to the main layout
        main_layout.addWidget(main_splitter)

    def update_statistics(self, stats=None):
        """
        Update the statistics tables with new data.
        stats: dict with keys 'top_talkers', 'top_ports', 'protocol_usage'.
        Each value should be a list of dicts/tuples as described below:
        {
            'top_talkers': [ {'ip': '1.2.3.4', 'packets': 100, 'bytes': 2048}, ... ],
            'top_ports':   [ {'port': 80, 'packets': 200, 'bytes': 4096}, ... ],
            'protocol_usage': [ {'protocol': 'TCP', 'packets': 300, 'bytes': 8192, 'percent': 60.0}, ... ]
        }
        """
        # Clear all tables
        self.topTalkersTable.setRowCount(0)
        self.topPortsTable.setRowCount(0)
        self.protocolUsageTable.setRowCount(0)

        if not stats:
            return

        # Top Talkers Table
        talkers = stats.get('top_talkers', [])
        for row, entry in enumerate(talkers):
            self.topTalkersTable.insertRow(row)
            self.topTalkersTable.setItem(row, 0, QTableWidgetItem(str(entry.get('ip', ''))))
            self.topTalkersTable.setItem(row, 1, QTableWidgetItem(str(entry.get('packets', ''))))
            self.topTalkersTable.setItem(row, 2, QTableWidgetItem(str(entry.get('bytes', ''))))

        # Top Ports Table
        ports = stats.get('top_ports', [])
        for row, entry in enumerate(ports):
            self.topPortsTable.insertRow(row)
            self.topPortsTable.setItem(row, 0, QTableWidgetItem(str(entry.get('port', ''))))
            self.topPortsTable.setItem(row, 1, QTableWidgetItem(str(entry.get('packets', ''))))
            self.topPortsTable.setItem(row, 2, QTableWidgetItem(str(entry.get('bytes', ''))))

        # Protocol Usage Table
        protocols = stats.get('protocol_usage', [])
        for row, entry in enumerate(protocols):
            self.protocolUsageTable.insertRow(row)
            self.protocolUsageTable.setItem(row, 0, QTableWidgetItem(str(entry.get('protocol', ''))))
            self.protocolUsageTable.setItem(row, 1, QTableWidgetItem(str(entry.get('packets', ''))))
            self.protocolUsageTable.setItem(row, 2, QTableWidgetItem(str(entry.get('bytes', ''))))
            percent = entry.get('percent', '')
            if isinstance(percent, float):
                percent = f"{percent:.2f}%"
            self.protocolUsageTable.setItem(row, 3, QTableWidgetItem(str(percent)))