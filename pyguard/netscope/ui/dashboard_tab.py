from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QSizePolicy, QPushButton, QFrame
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QPixmap, QIcon
import pyqtgraph as pg
import sqlite3
import json
import time

class DashboardTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(32, 32, 32, 32)
        main_layout.setSpacing(24)

        # Action Bar (fixed at top)
        action_bar = QHBoxLayout()
        action_bar.setSpacing(16)
        dashboard_icon = QLabel()
        dashboard_icon.setPixmap(QPixmap(':/icons/dashboard.png').scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        dashboard_icon.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        action_bar.addWidget(dashboard_icon)
        section_title = QLabel('Dashboard')
        section_title.setFont(QFont('Segoe UI', 22, QFont.Bold))
        section_title.setStyleSheet('color: #00BCD4;')
        action_bar.addWidget(section_title)
        action_bar.addStretch(1)
        self.refreshButton = QPushButton()
        self.refreshButton.setIcon(QIcon(':/icons/refresh.png'))
        self.refreshButton.setToolTip('Refresh Dashboard')
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

        # Card Grid Section (now just text, no cards)
        card_grid = QGridLayout()
        card_grid.setSpacing(36)
        self.totalPacketsLabel = QLabel('Total Packets Captured')
        self.totalPacketsLabel.setFont(QFont('Segoe UI', 16, QFont.Bold))
        self.totalPacketsLabel.setAlignment(Qt.AlignCenter)
        self.totalPacketsValue = QLabel('0')
        self.totalPacketsValue.setFont(QFont('Segoe UI', 32, QFont.Bold))
        self.totalPacketsValue.setAlignment(Qt.AlignCenter)
        self.packetsSecLabel = QLabel('Packets/sec')
        self.packetsSecLabel.setFont(QFont('Segoe UI', 16, QFont.Bold))
        self.packetsSecLabel.setAlignment(Qt.AlignCenter)
        self.packetsSecValue = QLabel('0')
        self.packetsSecValue.setFont(QFont('Segoe UI', 32, QFont.Bold))
        self.packetsSecValue.setAlignment(Qt.AlignCenter)
        self.threatsLabel = QLabel('Threats Detected')
        self.threatsLabel.setFont(QFont('Segoe UI', 16, QFont.Bold))
        self.threatsLabel.setAlignment(Qt.AlignCenter)
        self.threatsValue = QLabel('0')
        self.threatsValue.setFont(QFont('Segoe UI', 32, QFont.Bold))
        self.threatsValue.setAlignment(Qt.AlignCenter)
        self.activeFilterLabel = QLabel('Active Filter')
        self.activeFilterLabel.setFont(QFont('Segoe UI', 16, QFont.Bold))
        self.activeFilterLabel.setAlignment(Qt.AlignCenter)
        self.activeFilterValue = QLabel('All')
        self.activeFilterValue.setFont(QFont('Segoe UI', 32, QFont.Bold))
        self.activeFilterValue.setAlignment(Qt.AlignCenter)
        # Add to grid (label above value)
        card_grid.addWidget(self.totalPacketsLabel, 0, 0)
        card_grid.addWidget(self.packetsSecLabel, 0, 1)
        card_grid.addWidget(self.threatsLabel, 0, 2)
        card_grid.addWidget(self.activeFilterLabel, 0, 3)
        card_grid.addWidget(self.totalPacketsValue, 1, 0)
        card_grid.addWidget(self.packetsSecValue, 1, 1)
        card_grid.addWidget(self.threatsValue, 1, 2)
        card_grid.addWidget(self.activeFilterValue, 1, 3)
        main_layout.addLayout(card_grid)

        # Most recent packet info section
        self.recentPacketHeader = QLabel('Most Recent Packet')
        self.recentPacketHeader.setFont(QFont('Segoe UI', 16, QFont.Bold))
        self.recentPacketHeader.setStyleSheet('color: #FF9800; margin-top: 8px;')
        self.recentPacketHeader.setAlignment(Qt.AlignLeft)
        self.recentPacketInfo = QLabel('-')
        self.recentPacketInfo.setFont(QFont('Segoe UI', 14))
        self.recentPacketInfo.setStyleSheet('color: #E0E0E0;')
        self.recentPacketInfo.setAlignment(Qt.AlignLeft)
        main_layout.addWidget(self.recentPacketHeader)
        main_layout.addWidget(self.recentPacketInfo)

        # Charts Section Header
        charts_header = QLabel('Traffic Overview')
        charts_header.setFont(QFont('Segoe UI', 18, QFont.Bold))
        charts_header.setStyleSheet('color: #FF9800; margin-top: 16px;')
        main_layout.addWidget(charts_header)

        # Charts row in a card
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
        chart_row = QHBoxLayout(charts_card)
        chart_row.setContentsMargins(24, 24, 24, 24)
        chart_row.setSpacing(32)
        self.packetsLineChart = pg.PlotWidget()
        self.packetsLineChart.setBackground('w')
        self.packetsLineChart.setStyleSheet('background: transparent; border-radius: 24px;')
        self.packetsLineChart.setMinimumHeight(260)
        self.packetsLineChart.showGrid(x=True, y=True)
        self.packetsLineChart.setTitle('Live Packets Over Time', color='#B0B0B0', size='16pt')
        self.packetsLineChart.getAxis('left').setPen(pg.mkPen(color='#B0B0B0'))
        self.packetsLineChart.getAxis('bottom').setPen(pg.mkPen(color='#B0B0B0'))
        self.protocolPieChart = pg.PlotWidget()
        self.protocolPieChart.setBackground('w')
        self.protocolPieChart.setStyleSheet('background: transparent; border-radius: 24px;')
        self.protocolPieChart.setMinimumHeight(260)
        self.protocolPieChart.setTitle('Protocol Distribution', color='#B0B0B0', size='16pt')
        self.protocolPieChart.getAxis('left').setPen(pg.mkPen(color='#B0B0B0'))
        self.protocolPieChart.getAxis('bottom').setPen(pg.mkPen(color='#B0B0B0'))
        chart_row.addWidget(self.packetsLineChart)
        chart_row.addWidget(self.protocolPieChart)
        main_layout.addWidget(charts_card)
        main_layout.setStretch(0, 0)
        main_layout.setStretch(1, 1)
        main_layout.setStretch(2, 0)
        main_layout.setStretch(3, 2)

        # Timer to refresh stats and recent packet info
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_dashboard_stats)
        self.stats_timer.start(2000)  # 2 seconds
        self.refreshButton.clicked.connect(self.update_dashboard_stats)
        self.last_packet_time = None
        self.last_packet_count = 0

    def update_dashboard_stats(self):
        try:
            conn = sqlite3.connect('packets.db')
            cursor = conn.cursor()
            # Total packets
            cursor.execute('SELECT COUNT(*) FROM packets')
            total_packets = cursor.fetchone()[0]
            self.totalPacketsValue.setText(str(total_packets))
            # Packets/sec (calculate based on last 2 seconds)
            cursor.execute('SELECT id, timestamp FROM packets ORDER BY id DESC LIMIT 1')
            last_row = cursor.fetchone()
            packets_per_sec = 0
            if last_row:
                last_id, last_time_str = last_row
                if self.last_packet_time is not None:
                    # Calculate packets/sec based on count difference and time
                    time_format = '%Y-%m-%d %H:%M:%S'
                    try:
                        last_time = time.mktime(time.strptime(last_time_str, time_format))
                        delta_t = last_time - self.last_packet_time
                        delta_n = last_id - self.last_packet_count
                        if delta_t > 0:
                            packets_per_sec = int(delta_n / delta_t)
                    except Exception:
                        packets_per_sec = 0
                self.last_packet_time = time.mktime(time.strptime(last_time_str, '%Y-%m-%d %H:%M:%S'))
                self.last_packet_count = last_id
            self.packetsSecValue.setText(str(packets_per_sec))
            # Threats detected (not implemented)
            self.threatsValue.setText('N/A')
            # Active filter (not tracked here, so just show 'All')
            self.activeFilterValue.setText('All')
            # Most recent packet info
            cursor.execute('SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, details FROM packets ORDER BY id DESC LIMIT 1')
            pkt = cursor.fetchone()
            if pkt:
                ts, src, dst, proto, sport, dport, details_json = pkt
                details = {}
                try:
                    if details_json:
                        details = json.loads(details_json)
                except Exception:
                    pass
                info = f"{ts} | {src}:{sport} → {dst}:{dport} | {proto}"
                if 'http_data' in details:
                    info += f" | HTTP: {details['http_data'][:40]}"
                elif 'dns_qd' in details:
                    info += f" | DNS: {details['dns_qd']}"
                self.recentPacketInfo.setText(info)
            else:
                self.recentPacketInfo.setText('-')
            conn.close()
        except Exception as e:
            self.recentPacketInfo.setText(f'Error: {e}')

    def update_line_chart(self, x, y):
        self.packetsLineChart.clear()
        self.packetsLineChart.plot(x, y, pen=pg.mkPen('#1976D2', width=3))

    def update_pie_chart(self, labels, values, colors):
        self.protocolPieChart.clear()
        import numpy as np
        total = sum(values)
        angles = np.cumsum([0] + [v/total*360 for v in values])
        for i, (label, value, color) in enumerate(zip(labels, values, colors)):
            theta1, theta2 = angles[i], angles[i+1]
            pie = pg.QtGui.QGraphicsEllipseItem(-100, -100, 200, 200)
            pie.setStartAngle(int(theta1*16))
            pie.setSpanAngle(int((theta2-theta1)*16))
            pie.setBrush(pg.mkBrush(color))
            self.protocolPieChart.addItem(pie)

    def set_active_bpf_filter(self, bpf_filter):
        if bpf_filter:
            self.activeFilterValue.setText(bpf_filter)
        else:
            self.activeFilterValue.setText('All') 