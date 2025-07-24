import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QGroupBox, QLabel, QPushButton, QComboBox, QStatusBar, QTableWidget, QTableWidgetItem,
    QLineEdit, QTreeWidget, QTreeWidgetItem, QTextEdit, QPlainTextEdit, QCheckBox, QSlider,
    QFormLayout, QFileDialog, QTabBar, QSplitter, QMenuBar, QAction, QToolBar, QStyleFactory,
    QStackedWidget, QFrame
)
from PyQt5.QtCore import Qt, QTimer, QTime, QSize
from PyQt5.QtGui import QFont, QIcon, QColor, QPalette

# If you want to use PyQtGraph or Matplotlib, import here
# import pyqtgraph as pg
# from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
# from matplotlib.figure import Figure

# Helper for Lucide/Fluent icons (placeholder: use QIcon.fromTheme or your own SVGs)
def get_icon(name):
    # Replace with actual icon loading as needed
    return QIcon()

class DashboardTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        main_layout = QVBoxLayout(self)
        card_layout = QHBoxLayout()
        # Cards
        self.totalPacketsCard = self._create_card('Total Packets Captured', '0', 'totalPacketsCard')
        self.packetsSecCard = self._create_card('Packets/sec', '0', 'packetsSecCard')
        self.threatsCard = self._create_card('Threats Detected', '0', 'threatsCard')
        self.activeFilterCard = self._create_card('Active Filter', 'All', 'activeFilterCard')
        card_layout.addWidget(self.totalPacketsCard)
        card_layout.addWidget(self.packetsSecCard)
        card_layout.addWidget(self.threatsCard)
        card_layout.addWidget(self.activeFilterCard)
        main_layout.addLayout(card_layout)
        # Charts
        chart_layout = QHBoxLayout()
        self.packetsLineChart = QLabel('Live Line Chart (Packets over Time)')
        self.packetsLineChart.setObjectName('packetsLineChart')
        self.packetsLineChart.setAlignment(Qt.AlignCenter)
        self.protocolPieChart = QLabel('Protocol Distribution Pie Chart')
        self.protocolPieChart.setObjectName('protocolPieChart')
        self.protocolPieChart.setAlignment(Qt.AlignCenter)
        chart_layout.addWidget(self.packetsLineChart)
        chart_layout.addWidget(self.protocolPieChart)
        main_layout.addLayout(chart_layout)
        main_layout.setStretch(0, 1)
        main_layout.setStretch(1, 2)

    def _create_card(self, title, value, obj_name):
        card = QGroupBox(title)
        card.setObjectName(obj_name)
        layout = QVBoxLayout()
        label = QLabel(value)
        label.setObjectName(obj_name + 'Value')
        label.setAlignment(Qt.AlignCenter)
        label.setFont(QFont('Segoe UI', 24, QFont.Bold))
        layout.addWidget(label)
        card.setLayout(layout)
        return card

class LiveCaptureTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.packetTable = QTableWidget(0, 6)
        self.packetTable.setObjectName('packetTable')
        self.packetTable.setHorizontalHeaderLabels([
            'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Length', 'Info'
        ])
        self.packetTable.setAlternatingRowColors(True)
        layout.addWidget(self.packetTable)

class FilterTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        filter_row = QHBoxLayout()
        self.filterLineEdit = QLineEdit()
        self.filterLineEdit.setPlaceholderText('tcp port 443')
        self.filterLineEdit.setObjectName('filterLineEdit')
        self.presetCombo = QComboBox()
        self.presetCombo.setObjectName('presetCombo')
        self.presetCombo.addItems(['All', 'HTTP', 'HTTPS', 'DNS', 'ICMP', 'ARP'])
        self.applyButton = QPushButton('Apply')
        self.applyButton.setObjectName('applyButton')
        self.clearButton = QPushButton('Clear')
        self.clearButton.setObjectName('clearButton')
        filter_row.addWidget(self.filterLineEdit)
        filter_row.addWidget(self.presetCombo)
        filter_row.addWidget(self.applyButton)
        filter_row.addWidget(self.clearButton)
        layout.addLayout(filter_row)
        self.activeFilterLabel = QLabel('Current Filter: All')
        self.activeFilterLabel.setObjectName('activeFilterLabel')
        layout.addWidget(self.activeFilterLabel)

class PacketDetailsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        splitter = QSplitter(Qt.Horizontal)
        self.protocolTree = QTreeWidget()
        self.protocolTree.setObjectName('protocolTree')
        self.protocolTree.setHeaderLabel('Protocol Layers')
        self.hexDumpEdit = QTextEdit()
        self.hexDumpEdit.setObjectName('hexDumpEdit')
        self.hexDumpEdit.setReadOnly(True)
        splitter.addWidget(self.protocolTree)
        splitter.addWidget(self.hexDumpEdit)
        splitter.setSizes([200, 400])
        layout = QHBoxLayout(self)
        layout.addWidget(splitter)

class StatisticsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.statsTabs = QTabWidget()
        self.statsTabs.setObjectName('statsTabs')
        # Protocol Pie Chart
        self.protocolPie = QWidget()
        pie_layout = QVBoxLayout(self.protocolPie)
        self.protocolPieChart = QLabel('Protocol Pie Chart')
        self.protocolPieChart.setObjectName('protocolPieChartStats')
        self.protocolPieChart.setAlignment(Qt.AlignCenter)
        pie_toolbar = self._chart_toolbar('protocolPieExport', 'protocolPieRefresh')
        pie_layout.addWidget(pie_toolbar)
        pie_layout.addWidget(self.protocolPieChart)
        # Packet Size Histogram
        self.sizeHist = QWidget()
        hist_layout = QVBoxLayout(self.sizeHist)
        self.sizeHistogram = QLabel('Packet Size Histogram')
        self.sizeHistogram.setObjectName('sizeHistogram')
        self.sizeHistogram.setAlignment(Qt.AlignCenter)
        hist_toolbar = self._chart_toolbar('sizeHistExport', 'sizeHistRefresh')
        hist_layout.addWidget(hist_toolbar)
        hist_layout.addWidget(self.sizeHistogram)
        # Packet Timeline
        self.timeline = QWidget()
        timeline_layout = QVBoxLayout(self.timeline)
        self.timelineChart = QLabel('Packet Timeline')
        self.timelineChart.setObjectName('timelineChart')
        self.timelineChart.setAlignment(Qt.AlignCenter)
        timeline_toolbar = self._chart_toolbar('timelineExport', 'timelineRefresh')
        timeline_layout.addWidget(timeline_toolbar)
        timeline_layout.addWidget(self.timelineChart)
        self.statsTabs.addTab(self.protocolPie, 'Protocol')
        self.statsTabs.addTab(self.sizeHist, 'Size Histogram')
        self.statsTabs.addTab(self.timeline, 'Timeline')
        layout.addWidget(self.statsTabs)

    def _chart_toolbar(self, export_obj, refresh_obj):
        toolbar = QHBoxLayout()
        export_btn = QPushButton('Export')
        export_btn.setObjectName(export_obj)
        refresh_btn = QPushButton('⟳')
        refresh_btn.setObjectName(refresh_obj)
        refresh_btn.setFixedWidth(32)
        toolbar.addWidget(export_btn)
        toolbar.addWidget(refresh_btn)
        toolbar.addStretch()
        frame = QFrame()
        frame.setLayout(toolbar)
        return frame

class MLAlertsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        top_row = QHBoxLayout()
        self.mlToggle = QCheckBox('Enable ML Detection')
        self.mlToggle.setObjectName('mlToggle')
        self.thresholdSlider = QSlider(Qt.Horizontal)
        self.thresholdSlider.setObjectName('thresholdSlider')
        self.thresholdSlider.setMinimum(0)
        self.thresholdSlider.setMaximum(100)
        self.thresholdSlider.setValue(70)
        self.thresholdSlider.setSingleStep(1)
        self.thresholdLabel = QLabel('Threshold: 0.70')
        self.thresholdLabel.setObjectName('thresholdLabel')
        top_row.addWidget(self.mlToggle)
        top_row.addWidget(self.thresholdSlider)
        top_row.addWidget(self.thresholdLabel)
        top_row.addStretch()
        layout.addLayout(top_row)
        self.alertsTable = QTableWidget(0, 4)
        self.alertsTable.setObjectName('alertsTable')
        self.alertsTable.setHorizontalHeaderLabels([
            'Time', 'Source IP', 'Threat Type', 'Confidence'
        ])
        layout.addWidget(self.alertsTable)

class LogsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        filter_row = QHBoxLayout()
        self.systemLogCheck = QCheckBox('System Logs')
        self.systemLogCheck.setObjectName('systemLogCheck')
        self.packetLogCheck = QCheckBox('Packet Logs')
        self.packetLogCheck.setObjectName('packetLogCheck')
        self.mlLogCheck = QCheckBox('ML Logs')
        self.mlLogCheck.setObjectName('mlLogCheck')
        self.exportLogsButton = QPushButton('Export Logs')
        self.exportLogsButton.setObjectName('exportLogsButton')
        filter_row.addWidget(self.systemLogCheck)
        filter_row.addWidget(self.packetLogCheck)
        filter_row.addWidget(self.mlLogCheck)
        filter_row.addStretch()
        filter_row.addWidget(self.exportLogsButton)
        layout.addLayout(filter_row)
        self.logOutput = QPlainTextEdit()
        self.logOutput.setObjectName('logOutput')
        self.logOutput.setReadOnly(True)
        layout.addWidget(self.logOutput)

class SettingsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        form = QFormLayout(self)
        self.defaultInterfaceCombo = QComboBox()
        self.defaultInterfaceCombo.setObjectName('defaultInterfaceCombo')
        self.autosaveLocationButton = QPushButton('Choose...')
        self.autosaveLocationButton.setObjectName('autosaveLocationButton')
        self.autosaveLocationLabel = QLabel('Not set')
        self.autosaveLocationLabel.setObjectName('autosaveLocationLabel')
        autosave_row = QHBoxLayout()
        autosave_row.addWidget(self.autosaveLocationButton)
        autosave_row.addWidget(self.autosaveLocationLabel)
        autosave_widget = QWidget()
        autosave_widget.setLayout(autosave_row)
        self.soundAlertsCheck = QCheckBox('Enable Sound Alerts')
        self.soundAlertsCheck.setObjectName('soundAlertsCheck')
        self.mlModelPathButton = QPushButton('Choose...')
        self.mlModelPathButton.setObjectName('mlModelPathButton')
        self.mlModelPathLabel = QLabel('Not set')
        self.mlModelPathLabel.setObjectName('mlModelPathLabel')
        mlmodel_row = QHBoxLayout()
        mlmodel_row.addWidget(self.mlModelPathButton)
        mlmodel_row.addWidget(self.mlModelPathLabel)
        mlmodel_widget = QWidget()
        mlmodel_widget.setLayout(mlmodel_row)
        self.themeToggle = QComboBox()
        self.themeToggle.setObjectName('themeToggle')
        self.themeToggle.addItems(['Dark', 'Light'])
        form.addRow('Default Interface:', self.defaultInterfaceCombo)
        form.addRow('Autosave Location:', autosave_widget)
        form.addRow('', self.soundAlertsCheck)
        form.addRow('ML Model Path:', mlmodel_widget)
        form.addRow('Theme:', self.themeToggle)

class AboutTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        title = QLabel('PyGuard v1.0')
        title.setFont(QFont('Segoe UI', 20, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        desc = QLabel('Built with PyQt5, Scapy, scikit-learn')
        desc.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc)
        mit = QLabel('''MIT License\n\nCopyright (c) 2024\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the "Software"), to deal\nin the Software without restriction, including without limitation the rights\nto use, copy, modify, merge, publish, distribute, sublicense, and/or sell\ncopies of the Software, and to permit persons to whom the Software is\nfurnished to do so, subject to the following conditions: ...''')
        mit.setAlignment(Qt.AlignLeft)
        mit.setWordWrap(True)
        layout.addWidget(mit)
        links = QLabel('<a href="https://github.com/yourrepo">GitHub</a> | <a href="https://docs.example.com">Docs</a> | <a href="mailto:dev@example.com">Contact</a>')
        links.setOpenExternalLinks(True)
        links.setAlignment(Qt.AlignCenter)
        layout.addWidget(links)
        layout.addStretch()

class NetScopeMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('PyGuard – Network Analyzer')
        self.setMinimumSize(1400, 900)
        self.setObjectName('mainWindow')
        self.setWindowIcon(get_icon('activity'))
        # Central widget and layout
        central = QWidget()
        vbox = QVBoxLayout(central)
        # Top Toolbar
        self.toolbar = QToolBar()
        self.toolbar.setMovable(False)
        self.toolbar.setIconSize(QSize(32, 32))
        self.interfaceLabel = QLabel('Interface:')
        self.interfaceLabel.setObjectName('interfaceLabel')
        self.interfaceLabel.setFont(QFont('Segoe UI', 16))
        self.interfaceCombo = QComboBox()
        self.interfaceCombo.setObjectName('interfaceCombo')
        self.interfaceCombo.setMinimumWidth(200)
        self.interfaceCombo.setFont(QFont('Segoe UI', 16))
        self.startButton = QPushButton('▶ Start')
        self.startButton.setObjectName('startButton')
        self.startButton.setFont(QFont('Segoe UI', 16, QFont.Bold))
        self.stopButton = QPushButton('■ Stop')
        self.stopButton.setObjectName('stopButton')
        self.stopButton.setFont(QFont('Segoe UI', 16, QFont.Bold))
        self.activeFilterToolbarLabel = QLabel('Active Filter: All')
        self.activeFilterToolbarLabel.setObjectName('activeFilterToolbarLabel')
        self.activeFilterToolbarLabel.setFont(QFont('Segoe UI', 16))
        self.totalPacketsToolbarLabel = QLabel('Total Packets: 0')
        self.totalPacketsToolbarLabel.setObjectName('totalPacketsToolbarLabel')
        self.totalPacketsToolbarLabel.setFont(QFont('Segoe UI', 16))
        self.toolbar.addWidget(self.interfaceLabel)
        self.toolbar.addWidget(self.interfaceCombo)
        self.toolbar.addSeparator()
        self.toolbar.addWidget(self.startButton)
        self.toolbar.addWidget(self.stopButton)
        self.toolbar.addSeparator()
        self.toolbar.addWidget(self.activeFilterToolbarLabel)
        self.toolbar.addSeparator()
        self.toolbar.addWidget(self.totalPacketsToolbarLabel)
        vbox.addWidget(self.toolbar)
        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setObjectName('mainTabs')
        self.tabs.setFont(QFont('Segoe UI', 18))
        self.tabs.tabBar().setFont(QFont('Segoe UI', 22, QFont.Bold))
        self.tabs.tabBar().setStyleSheet('QTabBar::tab { min-width: 180px; min-height: 48px; font-size: 22px; }')
        self.dashboardTab = DashboardTab()
        self.liveCaptureTab = LiveCaptureTab()
        self.filterTab = FilterTab()
        self.packetDetailsTab = PacketDetailsTab()
        self.statisticsTab = StatisticsTab()
        self.mlAlertsTab = MLAlertsTab()
        self.logsTab = LogsTab()
        self.settingsTab = SettingsTab()
        self.aboutTab = AboutTab()
        self.tabs.addTab(self.dashboardTab, get_icon('activity'), 'Dashboard')
        self.tabs.addTab(self.liveCaptureTab, get_icon('list'), 'Live Capture')
        self.tabs.addTab(self.filterTab, get_icon('filter'), 'Filter')
        self.tabs.addTab(self.packetDetailsTab, get_icon('layers'), 'Packet Details')
        self.tabs.addTab(self.statisticsTab, get_icon('pie-chart'), 'Statistics')
        self.tabs.addTab(self.mlAlertsTab, get_icon('alert-triangle'), 'ML Alerts')
        self.tabs.addTab(self.logsTab, get_icon('file-text'), 'Logs')
        self.tabs.addTab(self.settingsTab, get_icon('settings'), 'Settings')
        self.tabs.addTab(self.aboutTab, get_icon('info'), 'About')
        vbox.addWidget(self.tabs)
        # Status Bar
        self.status = QStatusBar()
        self.status.setObjectName('statusBar')
        self.statusMsg = QLabel('Stopped')
        self.statusMsg.setObjectName('statusMsg')
        self.statusMsg.setFont(QFont('Segoe UI', 14, QFont.Bold))
        self.statusNIC = QLabel('NIC: -')
        self.statusNIC.setObjectName('statusNIC')
        self.statusNIC.setFont(QFont('Segoe UI', 14))
        self.statusML = QLabel('ML Detection: OFF (0.70)')
        self.statusML.setObjectName('statusML')
        self.statusML.setFont(QFont('Segoe UI', 14))
        self.statusTime = QLabel('00:00:00')
        self.statusTime.setObjectName('statusTime')
        self.statusTime.setFont(QFont('Segoe UI', 14, QFont.Bold))
        self.status.addWidget(self.statusMsg)
        self.status.addWidget(self.statusNIC)
        self.status.addWidget(self.statusML)
        self.status.addPermanentWidget(self.statusTime)
        self.setStatusBar(self.status)
        # Set central widget
        self.setCentralWidget(central)
        # Timer for clock
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_time)
        self.timer.start(1000)
        self.update_time()
        # Shortcuts
        self._setup_shortcuts()
        # Apply stylesheet
        self.setStyleSheet(self._get_stylesheet())

    def update_time(self):
        self.statusTime.setText(QTime.currentTime().toString('HH:mm:ss'))

    def _setup_shortcuts(self):
        self.startButton.setShortcut('Ctrl+R')
        self.stopButton.setShortcut('Ctrl+R')
        self.tabs.setTabToolTip(0, 'Dashboard')
        self.tabs.setTabToolTip(1, 'Live Capture')
        self.tabs.setTabToolTip(2, 'Filter')
        self.tabs.setTabToolTip(3, 'Packet Details')
        self.tabs.setTabToolTip(4, 'Statistics')
        self.tabs.setTabToolTip(5, 'ML Alerts')
        self.tabs.setTabToolTip(6, 'Logs')
        self.tabs.setTabToolTip(7, 'Settings')
        self.tabs.setTabToolTip(8, 'About')
        # Ctrl+F to focus filter
        from PyQt5.QtWidgets import QShortcut
        from PyQt5.QtGui import QKeySequence
        filter_shortcut = QShortcut(QKeySequence('Ctrl+F'), self)
        filter_shortcut.activated.connect(lambda: self.filterTab.filterLineEdit.setFocus())
        # F1 for help (About)
        QShortcutHelp = QAction('Help', self)
        QShortcutHelp.setShortcut('F1')
        QShortcutHelp.triggered.connect(lambda: self.tabs.setCurrentIndex(8))
        self.addAction(QShortcutHelp)

    def _get_stylesheet(self):
        return '''
        /* --- Global Backgrounds & Text --- */
        QMainWindow, QWidget {
            background-color: #1E1E2E;
            color: #E0E0E0;
            font-family: 'Segoe UI', 'Roboto', sans-serif;
            font-size: 18px;
        }
        /* --- Menu Bar & Toolbar --- */
        QMenuBar, QToolBar {
            background: #2B2B2B;
            color: #E0E0E0;
            border: none;
        }
        QToolBar {
            border-bottom: 1px solid #3C3C3C;
        }
        /* --- Tabs --- */
        QTabBar::tab {
            background: #2D2D42;
            color: #E0E0E0;
            border-radius: 6px 6px 0 0;
            padding: 12px 36px;
            font-size: 22px;
            font-weight: bold;
            min-width: 180px;
            min-height: 48px;
        }
        QTabBar::tab:selected {
            background-color: #1976D2;
            color: #FFFFFF;
            border-bottom: 3px solid #00BCD4;
        }
        QTabWidget::pane {
            border: 1px solid #23233A;
            border-radius: 6px;
        }
        /* --- Group Boxes (Cards) --- */
        QGroupBox {
            border: 2px solid #3A3A52;
            border-radius: 8px;
            margin-top: 16px;
            background: #2D2D42;
            font-size: 20px;
        }
        QGroupBox:title {
            subcontrol-origin: margin;
            left: 16px;
            padding: 0 6px 0 6px;
        }
        /* --- Buttons --- */
        QPushButton {
            background-color: #1976D2;
            color: #FFFFFF;
            border-radius: 8px;
            padding: 10px 24px;
            font-size: 18px;
            font-weight: bold;
            border: none;
        }
        QPushButton:hover {
            background-color: #2196F3;
            filter: brightness(1.1);
        }
        QPushButton:disabled {
            background-color: #4A4A4A;
            color: #808080;
        }
        /* --- Inputs & Controls --- */
        QComboBox, QLineEdit, QTextEdit, QPlainTextEdit, QTreeWidget, QTableWidget {
            background-color: #3C3C3C;
            color: #E0E0E0;
            border-radius: 8px;
            border: 2px solid #2B2B3C;
            font-size: 18px;
        }
        QLineEdit, QComboBox {
            border: 1.5px solid #4A4A4A;
        }
        QLineEdit:focus, QComboBox:focus {
            border: 2px solid #00BCD4;
        }
        /* --- Table Styles --- */
        QTableWidget {
            gridline-color: #2B2B3C;
            alternate-background-color: #333333;
            background-color: #3C3C3C;
            selection-background-color: #1976D2;
            selection-color: #FFFFFF;
            font-size: 18px;
        }
        QHeaderView::section {
            background-color: #2B2B2B;
            color: #E0E0E0;
            border: none;
            font-weight: bold;
            font-size: 18px;
            min-height: 36px;
        }
        /* --- Packet Type Indicators (for custom widgets/cells) --- */
        /* Use these as inline styles or setBackground/setForeground in code: */
        /* HTTP: #81C784, HTTPS: #4CAF50, TCP: #9C27B0, UDP: #FF9800, ICMP: #FFEB3B, Suspicious: #F44336 */
        /* --- ML Alerts --- */
        /* Normal: #4CAF50, Anomalous: QLinearGradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FF9800, stop:1 #F44336) */
        /* Alert badge: background #F44336, color #FFFFFF */
        /* --- Filter Chips/Tags --- */
        /* Use QWidget/QLabel with background: #3A3A52, color: #E0E0E0, border-radius: 12px; */
        /* Active: border: 2px solid #00BCD4; */
        /* --- Clear/Reset Button --- */
        QPushButton#clearButton {
            background-color: #E57373;
            color: #FFFFFF;
        }
        QPushButton#clearButton:hover {
            background-color: #F44336;
        }
        /* --- Export Buttons --- */
        QPushButton#exportCSVButton, QPushButton#exportButton {
            background-color: #1976D2;
            color: #FFFFFF;
        }
        QPushButton#exportCSVButton:hover, QPushButton#exportButton:hover {
            background-color: #00BCD4;
        }
        /* --- Status Bar & Indicators --- */
        QStatusBar {
            background: #2B2B2B;
            color: #E0E0E0;
            border-top: 1px solid #3C3C3C;
            font-size: 16px;
        }
        QLabel#statusMsg[status="connected"] {
            color: #4CAF50;
        }
        QLabel#statusMsg[status="disconnected"] {
            color: #F44336;
        }
        QLabel#statusTime {
            color: #00BCD4;
        }
        /* --- Progress Bars (for confidence, export, etc.) --- */
        QProgressBar {
            background-color: #3C3C3C;
            border: 1.5px solid #4A4A4A;
            border-radius: 8px;
            text-align: center;
            color: #E0E0E0;
        }
        QProgressBar::chunk {
            background-color: #00BCD4;
            border-radius: 8px;
        }
        /* --- Sliders --- */
        QSlider::groove:horizontal {
            border: 2px solid #00BCD4;
            height: 12px;
            background: #3A3A52;
            border-radius: 6px;
        }
        QSlider::handle:horizontal {
            background: #00BCD4;
            border: 2px solid #00BCD4;
            width: 28px;
            margin: -7px 0;
            border-radius: 14px;
        }
        /* --- Checkboxes --- */
        QCheckBox {
            spacing: 12px;
            font-size: 18px;
        }
        QCheckBox::indicator {
            width: 24px;
            height: 24px;
            border-radius: 6px;
            background: #3A3A52;
            border: 2px solid #00BCD4;
        }
        QCheckBox::indicator:checked {
            background: #4CAF50;
            border: 2px solid #4CAF50;
        }
        /* --- Splitters --- */
        QSplitter::handle {
            background: #4A4A4A;
        }
        QSplitter::handle:hover {
            background: #00BCD4;
        }
        /* --- Scrollbars --- */
        QScrollBar:vertical, QScrollBar:horizontal {
            background: #2B2B2B;
            width: 10px;
            margin: 2px;
            border-radius: 5px;
        }
        QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
            background: #4A4A4A;
            min-height: 20px;
            border-radius: 5px;
        }
        QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {
            background: #00BCD4;
        }
        QScrollBar::add-line, QScrollBar::sub-line {
            background: none;
        }
        /* --- Misc Text Colors --- */
        QLabel, QTableWidget, QTreeWidget, QLineEdit, QComboBox, QPushButton {
            color: #E0E0E0;
        }
        QLabel[role="secondary"], QTableWidget[role="secondary"] {
            color: #B0B0B0;
        }
        QLabel[role="muted"], QTableWidget[role="muted"] {
            color: #808080;
        }
        QLabel[role="highlight"], QTableWidget[role="highlight"] {
            color: #FFFFFF;
        }
        '''

def main():
    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create('Fusion'))
    window = NetScopeMainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main() 