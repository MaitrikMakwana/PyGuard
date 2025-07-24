from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QSizePolicy, QGraphicsPathItem
from PyQt5.QtCore import Qt, QPointF
from PyQt5.QtGui import QFont, QPixmap, QPainterPath, QBrush, QColor
import pyqtgraph as pg
import numpy as np

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
        self.protocolPieChart.showAxis('left', False)
        self.protocolPieChart.showAxis('bottom', False)
        self.protocolPieChart.setMouseEnabled(x=False, y=False)
        self.protocolPieChart.setMenuEnabled(False)
        # Lock aspect ratio so pie stays circular and centered
        self.protocolPieChart.getViewBox().setAspectLocked(True)
        # Remove or comment out the next line, as setPadding does not exist:
        # self.protocolPieChart.getViewBox().setPadding(0)
        # Center view range after widget is shown
        self.protocolPieChart.setXRange(-110, 110, padding=0)
        self.protocolPieChart.setYRange(-110, 110, padding=0)
        # Ensure the pie chart widget is centered in the layout
        chart_row.addStretch(1)
        chart_row.addWidget(self.packetsLineChart)
        chart_row.addStretch(1)
        chart_row.addWidget(self.protocolPieChart)
        chart_row.addStretch(1)
        main_layout.addLayout(chart_row)
        main_layout.setStretch(0, 1)
        main_layout.setStretch(1, 2)
        # Ensure the viewbox is centered after widget setup
        self.protocolPieChart.getViewBox().setRange(xRange=(-110, 110), yRange=(-110, 110), padding=0)

    def update_line_chart(self, x, y):
        self.packetsLineChart.clear()
        self.packetsLineChart.plot(x, y, pen=pg.mkPen('#1976D2', width=3))

    def update_pie_chart(self, labels, values, colors):
        self.protocolPieChart.clear()

        # Clear previous items from the ViewBox instead of the scene
        view_box = self.protocolPieChart.getViewBox()
        for item in list(view_box.addedItems):
            view_box.removeItem(item)

        total = sum(values)
        if total == 0:
            return

        radius = 100
        center = QPointF(0, 0)
        start_angle = 0

        for value, color in zip(values, colors):
            angle_span = 360 * value / total
            path = QPainterPath()
            path.moveTo(center)
            path.arcTo(-radius, -radius, 2 * radius, 2 * radius, start_angle, angle_span)
            path.lineTo(center)

            pie_slice = QGraphicsPathItem(path)
            pie_slice.setBrush(QBrush(QColor(color)))
            pie_slice.setPen(pg.mkPen(None))

            # Add pie slice to the ViewBox (not the scene directly)
            view_box.addItem(pie_slice)
            start_angle += angle_span

        # Disable auto range and manually center it
        view_box.enableAutoRange(False)
        view_box.setAspectLocked(True)
        margin = 20
        view_box.setRange(
            xRange=(-radius - margin, radius + margin),
            yRange=(-radius - margin, radius + margin),
            padding=0
        )

