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

        # Top row: Traffic volume (line) and Protocol usage (pie) in a card
        charts_card = QFrame()
        charts_card.setFrameShape(QFrame.StyledPanel)
        charts_card.setFrameShadow(QFrame.Raised)
        charts_card.setStyleSheet('''
            QFrame {
                background: rgba(44,44,64,0.45);
                border-radius: 24px;
                border: 1.5px solid rgba(255,255,255,0.10);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.10);
            }
        ''')
        top_row = QHBoxLayout(charts_card)
        top_row.setContentsMargins(24, 24, 24, 24)
        top_row.setSpacing(32)
        self.trafficLineChart = pg.PlotWidget()
        self.trafficLineChart.setBackground('w')
        self.trafficLineChart.setStyleSheet('background: transparent; border-radius: 24px;')
        self.trafficLineChart.setMinimumHeight(260)
        self.trafficLineChart.setTitle('Traffic Volume Over Time', color='#B0B0B0', size='16pt')
        self.trafficLineChart.showGrid(x=True, y=True)
        self.trafficLineChart.getAxis('left').setPen(pg.mkPen(color='#B0B0B0'))
        self.trafficLineChart.getAxis('bottom').setPen(pg.mkPen(color='#B0B0B0'))
        top_row.addWidget(self.trafficLineChart)
        self.protocolPieChart = pg.PlotWidget()
        self.protocolPieChart.setBackground('w')
        self.protocolPieChart.setStyleSheet('background: transparent; border-radius: 24px;')
        self.protocolPieChart.setMinimumHeight(260)
        self.protocolPieChart.setTitle('Protocol Usage Breakdown', color='#B0B0B0', size='16pt')
        top_row.addWidget(self.protocolPieChart)
        main_layout.addWidget(charts_card)

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

        # Middle row: Top Talkers and Port Stats in a card
        mid_card = QFrame()
        mid_card.setFrameShape(QFrame.StyledPanel)
        mid_card.setFrameShadow(QFrame.Raised)
        mid_card.setStyleSheet('''
            QFrame {
                background: rgba(44,44,64,0.45);
                border-radius: 18px;
                border: 1.5px solid rgba(255,255,255,0.10);
            }
        ''')
        mid_row = QHBoxLayout(mid_card)
        mid_row.setContentsMargins(18, 18, 18, 18)
        mid_row.setSpacing(32)
        self.topTalkersTable = QTableWidget(0, 3)
        self.topTalkersTable.setHorizontalHeaderLabels(['IP', 'Packets', 'Bytes'])
        self.topTalkersTable.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.topTalkersTable.setMinimumWidth(320)
        self.topTalkersTable.setStyleSheet('background: transparent; border-radius: 12px; color: #E0E0E0;')
        mid_row.addWidget(self.topTalkersTable)
        self.topPortsTable = QTableWidget(0, 3)
        self.topPortsTable.setHorizontalHeaderLabels(['Port', 'Packets', 'Bytes'])
        self.topPortsTable.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.topPortsTable.setMinimumWidth(320)
        self.topPortsTable.setStyleSheet('background: transparent; border-radius: 12px; color: #E0E0E0;')
        mid_row.addWidget(self.topPortsTable)
        main_layout.addWidget(mid_card)

        # Bottom row: Packet Size Histogram in a card
        hist_card = QFrame()
        hist_card.setFrameShape(QFrame.StyledPanel)
        hist_card.setFrameShadow(QFrame.Raised)
        hist_card.setStyleSheet('''
            QFrame {
                background: rgba(44,44,64,0.45);
                border-radius: 24px;
                border: 1.5px solid rgba(255,255,255,0.10);
            }
        ''')
        hist_layout = QVBoxLayout(hist_card)
        hist_layout.setContentsMargins(24, 24, 24, 24)
        hist_layout.setSpacing(16)
        self.sizeHistogram = pg.PlotWidget()
        self.sizeHistogram.setBackground('w')
        self.sizeHistogram.setStyleSheet('background: transparent; border-radius: 24px;')
        self.sizeHistogram.setMinimumHeight(220)
        self.sizeHistogram.setTitle('Packet Size Distribution', color='#B0B0B0', size='16pt')
        self.sizeHistogram.getAxis('left').setPen(pg.mkPen(color='#B0B0B0'))
        self.sizeHistogram.getAxis('bottom').setPen(pg.mkPen(color='#B0B0B0'))
        hist_layout.addWidget(self.sizeHistogram)
        main_layout.addWidget(hist_card)
        main_layout.addStretch(1)

    def update_statistics(self, stats=None):
        # This will be filled in app.py to update all charts/tables
        pass 