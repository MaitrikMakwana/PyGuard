from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame, QTableWidget, QTableWidgetItem, QSizePolicy
from PyQt5.QtCore import Qt
import pyqtgraph as pg

class StatisticsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(24)
        # Top row: Traffic volume (line) and Protocol usage (pie)
        top_row = QHBoxLayout()
        # Traffic Volume Over Time
        self.trafficLineChart = pg.PlotWidget()
        self.trafficLineChart.setBackground('w')
        self.trafficLineChart.setStyleSheet('background: rgba(44,44,64,0.45); border-radius: 24px;')
        self.trafficLineChart.setMinimumHeight(260)
        self.trafficLineChart.setTitle('Traffic Volume Over Time', color='#B0B0B0', size='16pt')
        self.trafficLineChart.showGrid(x=True, y=True)
        self.trafficLineChart.getAxis('left').setPen(pg.mkPen(color='#B0B0B0'))
        self.trafficLineChart.getAxis('bottom').setPen(pg.mkPen(color='#B0B0B0'))
        top_row.addWidget(self.trafficLineChart)
        # Protocol Usage Pie Chart
        self.protocolPieChart = pg.PlotWidget()
        self.protocolPieChart.setBackground('w')
        self.protocolPieChart.setStyleSheet('background: rgba(44,44,64,0.45); border-radius: 24px;')
        self.protocolPieChart.setMinimumHeight(260)
        self.protocolPieChart.setTitle('Protocol Usage Breakdown', color='#B0B0B0', size='16pt')
        top_row.addWidget(self.protocolPieChart)
        layout.addLayout(top_row)
        # Middle row: Top Talkers and Port Stats
        mid_row = QHBoxLayout()
        # Top Talkers Table
        self.topTalkersTable = QTableWidget(0, 3)
        self.topTalkersTable.setHorizontalHeaderLabels(['IP', 'Packets', 'Bytes'])
        self.topTalkersTable.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.topTalkersTable.setMinimumWidth(320)
        self.topTalkersTable.setStyleSheet('background: rgba(44,44,64,0.45); border-radius: 18px; color: #E0E0E0;')
        mid_row.addWidget(self.topTalkersTable)
        # Port Statistics Table
        self.topPortsTable = QTableWidget(0, 3)
        self.topPortsTable.setHorizontalHeaderLabels(['Port', 'Packets', 'Bytes'])
        self.topPortsTable.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.topPortsTable.setMinimumWidth(320)
        self.topPortsTable.setStyleSheet('background: rgba(44,44,64,0.45); border-radius: 18px; color: #E0E0E0;')
        mid_row.addWidget(self.topPortsTable)
        layout.addLayout(mid_row)
        # Bottom row: Packet Size Histogram
        self.sizeHistogram = pg.PlotWidget()
        self.sizeHistogram.setBackground('w')
        self.sizeHistogram.setStyleSheet('background: rgba(44,44,64,0.45); border-radius: 24px;')
        self.sizeHistogram.setMinimumHeight(220)
        self.sizeHistogram.setTitle('Packet Size Distribution', color='#B0B0B0', size='16pt')
        self.sizeHistogram.getAxis('left').setPen(pg.mkPen(color='#B0B0B0'))
        self.sizeHistogram.getAxis('bottom').setPen(pg.mkPen(color='#B0B0B0'))
        layout.addWidget(self.sizeHistogram)
        # Refresh button
        self.refreshButton = QPushButton('Refresh Statistics')
        self.refreshButton.setStyleSheet('background: #1976D2; color: #fff; border-radius: 10px; padding: 8px 24px; font-size: 16px;')
        layout.addWidget(self.refreshButton)
        layout.addStretch(1)

    def update_statistics(self, stats=None):
        # This will be filled in app.py to update all charts/tables
        pass 