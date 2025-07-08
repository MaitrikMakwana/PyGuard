from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QSizePolicy
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QPixmap
import pyqtgraph as pg

class GlassCard(QWidget):
    def __init__(self, icon_path, title, value, obj_name):
        super().__init__()
        self.setObjectName(obj_name)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setStyleSheet('''
            GlassCard {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 28px;
                border: 1.5px solid rgba(255,255,255,0.10);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.18);
            }
        ''')
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(10)
        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignCenter)
        if icon_path:
            icon_label.setPixmap(QPixmap(icon_path).scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        layout.addWidget(icon_label)
        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont('Segoe UI', 16, QFont.Bold))
        title_label.setStyleSheet('color: #E0E0E0;')
        layout.addWidget(title_label)
        self.value_label = QLabel(value)
        self.value_label.setObjectName(obj_name + 'Value')
        self.value_label.setAlignment(Qt.AlignCenter)
        self.value_label.setFont(QFont('Segoe UI', 36, QFont.Bold))
        self.value_label.setStyleSheet('color: #FFFFFF;')
        layout.addWidget(self.value_label)
        layout.addStretch(1)

class DashboardTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(32, 32, 32, 32)
        main_layout.setSpacing(32)
        card_grid = QGridLayout()
        card_grid.setSpacing(36)
        self.totalPacketsCard = GlassCard(None, 'Total Packets Captured', '0', 'totalPacketsCard')
        self.packetsSecCard = GlassCard(None, 'Packets/sec', '0', 'packetsSecCard')
        self.threatsCard = GlassCard(None, 'Threats Detected', '0', 'threatsCard')
        self.activeFilterCard = GlassCard(None, 'Active Filter', 'All', 'activeFilterCard')
        card_grid.addWidget(self.totalPacketsCard, 0, 0)
        card_grid.addWidget(self.packetsSecCard, 0, 1)
        card_grid.addWidget(self.threatsCard, 0, 2)
        card_grid.addWidget(self.activeFilterCard, 0, 3)
        main_layout.addLayout(card_grid)
        # Charts row
        chart_row = QHBoxLayout()
        # Live Line Chart
        self.packetsLineChart = pg.PlotWidget()
        self.packetsLineChart.setBackground('w')
        self.packetsLineChart.setStyleSheet('background: rgba(44,44,64,0.45); border-radius: 24px;')
        self.packetsLineChart.setMinimumHeight(260)
        self.packetsLineChart.showGrid(x=True, y=True)
        self.packetsLineChart.setTitle('Live Packets Over Time', color='#B0B0B0', size='16pt')
        self.packetsLineChart.getAxis('left').setPen(pg.mkPen(color='#B0B0B0'))
        self.packetsLineChart.getAxis('bottom').setPen(pg.mkPen(color='#B0B0B0'))
        # Pie Chart (custom widget)
        self.protocolPieChart = pg.PlotWidget()
        self.protocolPieChart.setBackground('w')
        self.protocolPieChart.setStyleSheet('background: rgba(44,44,64,0.45); border-radius: 24px;')
        self.protocolPieChart.setMinimumHeight(260)
        self.protocolPieChart.setTitle('Protocol Distribution', color='#B0B0B0', size='16pt')
        self.protocolPieChart.getAxis('left').setPen(pg.mkPen(color='#B0B0B0'))
        self.protocolPieChart.getAxis('bottom').setPen(pg.mkPen(color='#B0B0B0'))
        chart_row.addWidget(self.packetsLineChart)
        chart_row.addWidget(self.protocolPieChart)
        main_layout.addLayout(chart_row)
        main_layout.setStretch(0, 1)
        main_layout.setStretch(1, 2)

    def update_line_chart(self, x, y):
        self.packetsLineChart.clear()
        self.packetsLineChart.plot(x, y, pen=pg.mkPen('#1976D2', width=3))

    def update_pie_chart(self, labels, values, colors):
        self.protocolPieChart.clear()
        # Pie chart using bar graph as workaround (pyqtgraph has no native pie)
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