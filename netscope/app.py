import sys
import os
import csv
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox, QTabWidget, QToolBar, QLabel, QComboBox, QPushButton, QVBoxLayout, QWidget, QFileDialog, QHBoxLayout, QSizePolicy, QStyle, QAction, QVBoxLayout
from PyQt5.QtCore import QTimer, QSize, QPropertyAnimation, QEasingCurve
from netscope.ui.dashboard_tab import DashboardTab
from netscope.ui.live_capture_tab import LiveCaptureTab
from netscope.ui.filter_tab import FilterTab
from netscope.ui.packet_details_tab import PacketDetailsTab
from netscope.ui.statistics_tab import StatisticsTab
from netscope.ui.ml_alerts_tab import MLAlertsTab
from netscope.ui.logs_tab import LogsTab
from netscope.ui.settings_tab import SettingsTab
from netscope.ui.about_tab import AboutTab
from netscope.backend.capture import CaptureManager
import sqlite3
from scapy.all import get_if_list, sniff
import re
from PyQt5.QtWidgets import QGraphicsOpacityEffect, QProgressBar
from PyQt5.QtWidgets import QWidget, QHBoxLayout, QSizePolicy
from PyQt5.QtCore import Qt
import pyqtgraph as pg
import numpy as np

class NetScopeApp(QMainWindow):
    def __init__(self):
        super().__init__()
        from PyQt5.QtGui import QFont, QIcon
        self.setWindowTitle('NetScope – Network Analyzer')
        self.setMinimumSize(1400, 900)
        # Central widget and layout
        central = QWidget()
        vbox = QVBoxLayout(central)
        # Unified Toolbar: all buttons in a single rectangular bar
        self.toolbar = QToolBar()
        self.toolbar.setMovable(False)
        self.toolbar.setIconSize(QSize(28, 28))
        self.toolbar.setStyleSheet('''
            QToolBar {
                background: #23233A;
                border-radius: 14px;
                border: 1.5px solid #2B2B3C;
                margin: 18px 32px 8px 32px;
                padding: 8px 18px;
            }
        ''')
        toolbar_widget = QWidget()
        toolbar_layout = QHBoxLayout(toolbar_widget)
        toolbar_layout.setContentsMargins(0, 0, 0, 0)
        toolbar_layout.setSpacing(36)  # Increased spacing for clarity
        style = QApplication.style()
        # Helper to create icon+label vertical button
        def make_toolbar_button(icon, text, tooltip, slot):
            btn_widget = QWidget()
            btn_layout = QVBoxLayout(btn_widget)
            btn_layout.setContentsMargins(0, 0, 0, 0)
            btn_layout.setSpacing(2)
            btn = QPushButton()
            btn.setIcon(icon)
            btn.setToolTip(tooltip)
            btn.setFixedSize(40, 40)
            btn.setStyleSheet('border-radius: 14px; background: #1976D2; color: #fff;')
            btn.clicked.connect(slot)
            label = QLabel(text)
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet('color: #E0E0E0; font-size: 12px;')
            btn_layout.addWidget(btn)
            btn_layout.addWidget(label)
            return btn_widget, btn
        # Start
        start_widget, self.startButton = make_toolbar_button(
            style.standardIcon(QStyle.SP_MediaPlay), 'Start', 'Start Capture', self.start_capture)
        # Stop
        stop_widget, self.stopButton = make_toolbar_button(
            style.standardIcon(QStyle.SP_MediaStop), 'Stop', 'Stop Capture', self.stop_capture)
        # Clear
        clear_widget, self.clearAllButton = make_toolbar_button(
            style.standardIcon(QStyle.SP_TrashIcon), 'Clear', 'Clear All Packets', self.clear_all_packets)
        # Export
        export_widget, self.exportCSVButton = make_toolbar_button(
            style.standardIcon(QStyle.SP_DialogSaveButton), 'Export', 'Export as CSV', self.export_csv)
        # Import
        import_widget, self.importButton = make_toolbar_button(
            style.standardIcon(QStyle.SP_DialogOpenButton), 'Import', 'Import Packets (CSV/PCAP)', self.import_packets)
        # Add all buttons in a row
        toolbar_layout.addWidget(start_widget)
        toolbar_layout.addWidget(stop_widget)
        toolbar_layout.addWidget(clear_widget)
        toolbar_layout.addWidget(export_widget)
        toolbar_layout.addWidget(import_widget)
        toolbar_layout.addStretch(1)
        self.toolbar.addWidget(toolbar_widget)
        vbox.addWidget(self.toolbar)
        # Modern Tab Bar
        self.tabs = QTabWidget()
        self.tabs.setFont(QFont('Segoe UI', 18))
        self.tabs.tabBar().setFont(QFont('Segoe UI', 20, QFont.Bold))
        self.tabs.setStyleSheet('''
            QTabBar::tab {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 18px;
                min-width: 160px;
                min-height: 48px;
                margin: 0 8px;
                padding: 12px 32px;
                color: #E0E0E0;
                font-size: 20px;
                font-weight: bold;
                transition: all 0.2s;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1976D2, stop:1 #00BCD4);
                color: #FFFFFF;
                box-shadow: 0 2px 12px 0 rgba(25, 118, 210, 0.18);
            }
            QTabBar::tab:hover {
                background: rgba(25, 118, 210, 0.18);
                color: #FFFFFF;
            }
            QTabWidget::pane {
                border: none;
                margin-top: 8px;
            }
        ''')
        self.dashboardTab = DashboardTab()
        self.liveCaptureTab = LiveCaptureTab()
        self.filterTab = FilterTab()
        self.packetDetailsTab = PacketDetailsTab()
        self.statisticsTab = StatisticsTab()
        self.mlAlertsTab = MLAlertsTab()
        self.logsTab = LogsTab()
        self.settingsTab = SettingsTab()
        self.aboutTab = AboutTab()
        self.tabs.addTab(self.dashboardTab, 'Dashboard')
        self.tabs.addTab(self.liveCaptureTab, 'Live Capture')
        self.tabs.addTab(self.filterTab, 'Filter')
        self.tabs.addTab(self.packetDetailsTab, 'Packet Details')
        self.tabs.addTab(self.statisticsTab, 'Statistics')
        self.tabs.addTab(self.mlAlertsTab, 'ML Alerts')
        self.tabs.addTab(self.logsTab, 'Logs')
        self.tabs.addTab(self.settingsTab, 'Settings')
        self.tabs.addTab(self.aboutTab, 'About')
        vbox.addWidget(self.tabs)
        vbox.setStretch(1, 1)  # Make tabs area expand
        self.setCentralWidget(central)
        # Backend
        self.capture_manager = CaptureManager()
        # Connect UI actions
        self._connect_signals()
        # Connect packet selection to details tab
        self.liveCaptureTab.packetTable.cellClicked.connect(self.show_packet_details)
        # Timer for live updates
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_live_table)
        self.update_timer.start(1000)
        # Apply professional theme stylesheet
        self.setStyleSheet(self._get_stylesheet())
        # --- Animations ---
        self._setup_tab_fade_animation()
        self._setup_button_animations()
        # For progress bar animation, see update_progress_bar_value method below
        # Add interactive welcome/info panel to Dashboard
        self._add_dashboard_welcome()
        # Connect statistics refresh button
        self.statisticsTab.refreshButton.clicked.connect(self.update_statistics_tab)
        # Update statistics when tab is shown
        self.tabs.currentChanged.connect(self._on_tab_changed)

    def _setup_tab_fade_animation(self):
        self._tab_fade_effects = {}
        self.tabs.currentChanged.connect(self._animate_tab_fade_in)
        # Set initial effect
        current_widget = self.tabs.currentWidget()
        if current_widget:
            effect = QGraphicsOpacityEffect(current_widget)
            current_widget.setGraphicsEffect(effect)
            effect.setOpacity(1.0)
            self._tab_fade_effects[current_widget] = effect

    def _animate_tab_fade_in(self, index):
        widget = self.tabs.widget(index)
        if widget is None:
            return
        effect = self._tab_fade_effects.get(widget)
        if not effect:
            effect = QGraphicsOpacityEffect(widget)
            widget.setGraphicsEffect(effect)
            self._tab_fade_effects[widget] = effect
        anim = QPropertyAnimation(effect, b"opacity")
        anim.setDuration(350)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.InOutQuad)
        anim.start()
        # Keep reference to avoid garbage collection
        self._current_tab_anim = anim

    def _setup_button_animations(self):
        for btn in [self.startButton, self.stopButton, self.clearAllButton, self.exportCSVButton]:
            btn.pressed.connect(lambda b=btn: self._animate_button_press(b))
            btn.released.connect(lambda b=btn: self._animate_button_release(b))

    def _animate_button_press(self, btn):
        anim = QPropertyAnimation(btn, b"geometry")
        anim.setDuration(100)
        rect = btn.geometry()
        shrink = rect.adjusted(4, 4, -4, -4)
        anim.setStartValue(rect)
        anim.setEndValue(shrink)
        anim.setEasingCurve(QEasingCurve.OutQuad)
        anim.start()
        btn._press_anim = anim

    def _animate_button_release(self, btn):
        anim = QPropertyAnimation(btn, b"geometry")
        anim.setDuration(100)
        rect = btn.geometry()
        grow = rect.adjusted(-4, -4, 4, 4)
        anim.setStartValue(rect)
        anim.setEndValue(grow)
        anim.setEasingCurve(QEasingCurve.OutQuad)
        anim.start()
        btn._release_anim = anim

    def update_progress_bar_value(self, progress_bar: QProgressBar, value: int):
        # Call this method instead of setValue for smooth animation
        anim = QPropertyAnimation(progress_bar, b"value")
        anim.setDuration(400)
        anim.setStartValue(progress_bar.value())
        anim.setEndValue(value)
        anim.setEasingCurve(QEasingCurve.InOutQuad)
        anim.start()
        progress_bar._value_anim = anim

    def _connect_signals(self):
        self.startButton.clicked.connect(self.start_capture)
        self.stopButton.clicked.connect(self.stop_capture)
        self.filterTab.applyButton.clicked.connect(self.apply_filter)
        self.filterTab.clearButton.clicked.connect(self.clear_filter)
        self.clearAllButton.clicked.connect(self.clear_all_packets)
        self.exportCSVButton.clicked.connect(self.export_csv)
        self.filterTab.filterLineEdit.returnPressed.connect(self.apply_filter)

    def start_capture(self):
        interface = self._auto_select_interface()
        bpf_filter = self.filterTab.filterLineEdit.text()
        self.capture_manager.start(interface=interface, bpf_filter=bpf_filter)
        QMessageBox.information(self, 'Capture Started', f'Capturing on {interface} with filter: {bpf_filter}')

    def stop_capture(self):
        self.capture_manager.stop()
        QMessageBox.information(self, 'Capture Stopped', 'Packet capture stopped.')

    def apply_filter(self):
        self.update_live_table()

    def clear_filter(self):
        self.filterTab.filterLineEdit.clear()
        self.update_live_table()

    def _parse_filter(self, filter_str):
        # Supports: ip.src==, ip.dst==, tcp.port==, udp.port==, protocol==, BPF like 'tcp port 80', AND (&&), OR (||)
        if not filter_str.strip():
            return None, []
        # Split by OR (||)
        or_clauses = [c.strip() for c in filter_str.split('||') if c.strip()]
        or_sql = []
        or_params = []
        for or_clause in or_clauses:
            # Split by AND (&&)
            and_clauses = [a.strip() for a in or_clause.split('&&') if a.strip()]
            and_sql = []
            and_params = []
            for clause in and_clauses:
                # BPF-like: tcp, udp, icmp, arp, dns, tcp port 80, etc.
                bpf_match = re.match(r'^(tcp|udp|icmp|arp|dns)( port (\d+))?$', clause, re.IGNORECASE)
                if bpf_match:
                    proto = bpf_match.group(1).upper()
                    port = bpf_match.group(3)
                    sql = 'protocol = ?'
                    params = [proto]
                    if port:
                        sql += ' AND (src_port = ? OR dst_port = ?)'
                        params += [port, port]
                    and_sql.append(sql)
                    and_params.extend(params)
                    continue
                # Wireshark-like field filters
                m_ip_src = re.match(r'ip\.src==([\d\.]+)', clause)
                m_ip_dst = re.match(r'ip\.dst==([\d\.]+)', clause)
                m_tcp_port = re.match(r'tcp\.port==([\d]+)', clause)
                m_udp_port = re.match(r'udp\.port==([\d]+)', clause)
                m_proto = re.match(r'protocol==([A-Za-z0-9]+)', clause)
                if m_ip_src:
                    and_sql.append('src_ip = ?')
                    and_params.append(m_ip_src.group(1))
                elif m_ip_dst:
                    and_sql.append('dst_ip = ?')
                    and_params.append(m_ip_dst.group(1))
                elif m_tcp_port:
                    and_sql.append('(src_port = ? OR dst_port = ?)')
                    and_params += [m_tcp_port.group(1), m_tcp_port.group(1)]
                elif m_udp_port:
                    and_sql.append('(src_port = ? OR dst_port = ?)')
                    and_params += [m_udp_port.group(1), m_udp_port.group(1)]
                elif m_proto:
                    and_sql.append('protocol = ?')
                    and_params.append(m_proto.group(1).upper())
            if and_sql:
                or_sql.append('(' + ' AND '.join(and_sql) + ')')
                or_params.extend(and_params)
        if or_sql:
            return ' OR '.join(or_sql), or_params
        return None, []

    def update_live_table(self):
        conn = sqlite3.connect('packets.db')
        cursor = conn.cursor()
        # Live Capture tab: show all packets
        cursor.execute('SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size FROM packets ORDER BY id DESC')
        all_rows = cursor.fetchall()
        self.liveCaptureTab.packetTable.setRowCount(len(all_rows))
        for row_idx, row in enumerate(all_rows):
            for col_idx, value in enumerate(row):
                self.liveCaptureTab.packetTable.setItem(row_idx, col_idx, self.make_table_item(str(value)))
        # Filter tab: show only filtered packets
        filter_str = self.filterTab.filterLineEdit.text().strip()
        sql, params = self._parse_filter(filter_str)
        if sql:
            query = f'SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size FROM packets WHERE {sql} ORDER BY id DESC'
            cursor.execute(query, params)
            filter_rows = cursor.fetchall()
        else:
            filter_rows = all_rows
        self.filterTab.filterTable.setRowCount(len(filter_rows))
        for row_idx, row in enumerate(filter_rows):
            for col_idx, value in enumerate(row):
                self.filterTab.filterTable.setItem(row_idx, col_idx, self.make_table_item(str(value)))
        # --- Dashboard updates ---
        total_packets = len(all_rows)
        self.dashboardTab.totalPacketsCard.findChild(QLabel, 'totalPacketsCardValue').setText(str(total_packets))
        # Packets/sec (calculate from timestamps)
        from datetime import datetime, timedelta
        import collections
        if all_rows:
            times = [datetime.strptime(r[0], '%Y-%m-%d %H:%M:%S') for r in all_rows]
            if len(times) > 1:
                duration = (times[0] - times[-1]).total_seconds() or 1
                pps = int(len(times) / duration)
            else:
                pps = len(times)
        else:
            pps = 0
        self.dashboardTab.packetsSecCard.findChild(QLabel, 'packetsSecCardValue').setText(str(pps))
        # Threats Detected (placeholder: count rows in ML Alerts table if available)
        try:
            cursor.execute('SELECT COUNT(*) FROM packets WHERE protocol = "THREAT"')
            threats = cursor.fetchone()[0]
        except Exception:
            threats = 0
        self.dashboardTab.threatsCard.findChild(QLabel, 'threatsCardValue').setText(str(threats))
        # Active Filter
        active_filter = self.filterTab.filterLineEdit.text() or 'All'
        self.dashboardTab.activeFilterCard.findChild(QLabel, 'activeFilterCardValue').setText(active_filter)
        # --- Live Chart Updates ---
        # 1. Line chart: packets per second over last 60 seconds
        now = datetime.now()
        window = timedelta(seconds=60)
        time_buckets = collections.OrderedDict()
        for i in range(59, -1, -1):
            t = now - timedelta(seconds=i)
            label = t.strftime('%H:%M:%S')
            time_buckets[label] = 0
        for row in all_rows:
            try:
                t = datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S')
                if now - window < t <= now:
                    label = t.strftime('%H:%M:%S')
                    if label in time_buckets:
                        time_buckets[label] += 1
            except Exception:
                pass
        x = list(time_buckets.keys())
        y = list(time_buckets.values())
        self.dashboardTab.update_line_chart(list(range(len(x))), y)  # Use index for x axis for better performance
        # 2. Pie chart: protocol distribution
        protocol_counts = collections.Counter(row[3].upper() for row in all_rows)
        protocol_order = ['TCP', 'UDP', 'ICMP', 'ARP', 'DNS', 'HTTP', 'OTHER']
        labels = []
        values = []
        colors = []
        color_map = {
            'TCP': '#1976D2',
            'UDP': '#00BCD4',
            'ICMP': '#43A047',
            'ARP': '#FBC02D',
            'DNS': '#8E24AA',
            'HTTP': '#E64A19',
            'OTHER': '#757575',
        }
        for proto in protocol_order:
            count = protocol_counts.get(proto, 0)
            if count > 0:
                labels.append(proto)
                values.append(count)
                colors.append(color_map.get(proto, '#757575'))
        # Add any other protocols
        for proto, count in protocol_counts.items():
            if proto not in protocol_order and count > 0:
                labels.append(proto)
                values.append(count)
                colors.append('#757575')
        if values:
            self.dashboardTab.update_pie_chart(labels, values, colors)
        else:
            self.dashboardTab.protocolPieChart.clear()
        conn.close()

    @staticmethod
    def make_table_item(text):
        from PyQt5.QtWidgets import QTableWidgetItem
        item = QTableWidgetItem(text)
        item.setFlags(item.flags() ^ 2)  # Not editable
        return item

    def clear_all_packets(self):
        reply = QMessageBox.question(self, 'Clear All', 'Are you sure you want to delete all captured packets?', QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            conn = sqlite3.connect('packets.db')
            cursor = conn.cursor()
            cursor.execute('DELETE FROM packets')
            conn.commit()
            conn.close()
            self.update_live_table()
            QMessageBox.information(self, 'Cleared', 'All packets have been deleted.')

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Export Packets as CSV', '', 'CSV Files (*.csv)')
        if not path:
            return
        conn = sqlite3.connect('packets.db')
        cursor = conn.cursor()
        cursor.execute('SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size FROM packets ORDER BY id DESC')
        rows = cursor.fetchall()
        conn.close()
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Src Port', 'Dst Port', 'Size'])
            writer.writerows(rows)
        QMessageBox.information(self, 'Exported', f'Packets exported to {path}')

    def import_packets(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Import Packets', '', 'Packet Files (*.csv *.pcap);;All Files (*)')
        if not path:
            return
        imported = 0
        if path.lower().endswith('.csv'):
            import csv, json
            conn = sqlite3.connect('packets.db')
            cursor = conn.cursor()
            with open(path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                header = next(reader, None)
                for row in reader:
                    if len(row) < 7:
                        continue
                    timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size = row[:7]
                    details = '{}'
                    if len(row) >= 8 and row[7].strip():
                        try:
                            # Validate JSON
                            json.loads(row[7])
                            details = row[7]
                        except Exception:
                            details = '{}'
                    cursor.execute(
                        "INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, int(size), details)
                    )
                    imported += 1
            conn.commit()
            conn.close()
            self.update_live_table()
            QMessageBox.information(self, 'Import', f'Imported {imported} packets from {path}')
        else:
            QMessageBox.information(self, 'Import', f'Imported file: {path}')

    def _auto_select_interface(self):
        interfaces = get_if_list()
        for iface in interfaces:
            pkts = sniff(iface=iface, count=1, timeout=1, store=1)
            if pkts:
                return iface
        return interfaces[0] if interfaces else None

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

    def _add_dashboard_welcome(self):
        # Add a glassmorphic info panel at the top of the dashboard with interactive tips
        if hasattr(self, 'dashboardTab'):
            from PyQt5.QtWidgets import QVBoxLayout, QLabel, QPushButton, QHBoxLayout
            info_panel = QWidget()
            info_panel.setStyleSheet('''
                background: rgba(44, 44, 64, 0.65);
                border-radius: 20px;
                border: 1.5px solid rgba(255,255,255,0.10);
                box-shadow: 0 4px 24px 0 rgba(31, 38, 135, 0.10);
            ''')
            info_layout = QVBoxLayout(info_panel)
            info_layout.setContentsMargins(32, 24, 32, 24)
            info_layout.setSpacing(10)
            title = QLabel('👋 Welcome to NetScope!')
            title.setStyleSheet('color: #FFFFFF; font-size: 22px; font-weight: bold;')
            info_layout.addWidget(title)
            steps = QLabel('''<ul style="margin-left: 0; padding-left: 18px; color: #B0B0B0; font-size: 16px;">
<li><b>Start</b> a live capture with the ▶ button above.</li>
<li>Or <b>import</b> a packet file (CSV/PCAP) with the Import button.</li>
<li>Use <b>Filter</b> to search for specific traffic.</li>
<li>Click on a packet to see detailed info and protocol layers.</li>
<li>Check the <b>ML Alerts</b> tab for AI-powered threat detection.</li>
</ul>''')
            steps.setStyleSheet('color: #B0B0B0; font-size: 16px;')
            steps.setWordWrap(True)
            info_layout.addWidget(steps)
            # Optionally, add a dismiss button
            dismiss_btn = QPushButton('Got it!')
            dismiss_btn.setStyleSheet('background: #1976D2; color: #fff; border-radius: 10px; padding: 6px 18px; font-size: 15px;')
            def hide_panel():
                info_panel.hide()
            dismiss_btn.clicked.connect(hide_panel)
            btn_row = QHBoxLayout()
            btn_row.addStretch(1)
            btn_row.addWidget(dismiss_btn)
            info_layout.addLayout(btn_row)
            # Insert at the top of the dashboard layout
            dash_layout = self.dashboardTab.layout()
            dash_layout.insertWidget(0, info_panel)

    def show_packet_details(self, row, col):
        # Get packet data from the selected row in the table
        table = self.liveCaptureTab.packetTable
        # Get timestamp and src_ip as unique keys (or use rowid if available)
        timestamp = table.item(row, 0).text() if table.item(row, 0) else ''
        src_ip = table.item(row, 1).text() if table.item(row, 1) else ''
        # Fetch details JSON from DB for this packet
        import sqlite3, json
        conn = sqlite3.connect('packets.db')
        cursor = conn.cursor()
        cursor.execute("SELECT details FROM packets WHERE timestamp=? AND src_ip=? LIMIT 1", (timestamp, src_ip))
        result = cursor.fetchone()
        details = {}
        if result and result[0]:
            try:
                details = json.loads(result[0])
            except Exception:
                details = {}
        conn.close()
        # Build protocol tree
        tree = self.packetDetailsTab.protocolTree
        tree.clear()
        from PyQt5.QtWidgets import QTreeWidgetItem
        # Layer order for display
        layer_fields = [
            ('Ethernet', ['eth_src', 'eth_dst', 'eth_type']),
            ('IP', ['ip_version', 'ip_ihl', 'ip_tos', 'ip_len', 'ip_id', 'ip_flags', 'ip_frag', 'ip_ttl', 'ip_proto', 'ip_chksum', 'ip_options']),
            ('TCP', ['tcp_seq', 'tcp_ack', 'tcp_dataofs', 'tcp_reserved', 'tcp_flags', 'tcp_window', 'tcp_chksum', 'tcp_urgptr', 'tcp_options']),
            ('UDP', ['udp_len', 'udp_chksum']),
            ('DNS', ['dns_id', 'dns_qr', 'dns_opcode', 'dns_aa', 'dns_tc', 'dns_rd', 'dns_ra', 'dns_z', 'dns_rcode', 'dns_qdcount', 'dns_ancount', 'dns_nscount', 'dns_arcount', 'dns_qd', 'dns_an']),
            ('ICMP', ['icmp_type', 'icmp_code', 'icmp_chksum', 'icmp_id', 'icmp_seq']),
            ('ARP', ['arp_hwtype', 'arp_ptype', 'arp_hwlen', 'arp_plen', 'arp_op', 'arp_hwsrc', 'arp_psrc', 'arp_hwdst', 'arp_pdst']),
            ('HTTP', ['http_data']),
        ]
        for layer, fields in layer_fields:
            layer_present = any(f in details for f in fields)
            if layer_present:
                layer_item = QTreeWidgetItem([layer])
                for f in fields:
                    if f in details:
                        QTreeWidgetItem(layer_item, [f"{f}: {details[f]}"])
                tree.addTopLevelItem(layer_item)
        # Show raw/hex payload if available
        hex_dump = details.get('raw', '')
        if hex_dump:
            try:
                # Show as hex and ASCII
                hex_bytes = bytes.fromhex(hex_dump)
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in hex_bytes)
                hex_lines = []
                for i in range(0, len(hex_bytes), 16):
                    chunk = hex_bytes[i:i+16]
                    hex_part = ' '.join(f'{b:02X}' for b in chunk)
                    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                    hex_lines.append(f'{i:04X}  {hex_part:<48}  {ascii_part}')
                self.packetDetailsTab.hexDumpEdit.setPlainText('\n'.join(hex_lines))
            except Exception:
                self.packetDetailsTab.hexDumpEdit.setPlainText(hex_dump)
        else:
            self.packetDetailsTab.hexDumpEdit.setPlainText('')
        # Switch to Packet Details tab
        self.tabs.setCurrentWidget(self.packetDetailsTab)

    def update_statistics_tab(self):
        print("DEBUG: update_statistics_tab called")
        import sqlite3, collections
        from datetime import datetime, timedelta
        import numpy as np
        conn = sqlite3.connect('packets.db')
        cursor = conn.cursor()
        cursor.execute('SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size FROM packets ORDER BY id DESC')
        all_rows = cursor.fetchall()
        # 1. Traffic volume over time (packets per minute for last 60 min)
        now = datetime.now()
        window = timedelta(minutes=60)
        time_buckets = collections.OrderedDict()
        for i in range(59, -1, -1):
            t = now - timedelta(minutes=i)
            label = t.strftime('%H:%M')
            time_buckets[label] = 0
        for row in all_rows:
            try:
                t = datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S')
                if now - window < t <= now:
                    label = t.strftime('%H:%M')
                    if label in time_buckets:
                        time_buckets[label] += 1
            except Exception:
                pass
        x = list(range(len(time_buckets)))
        y = list(time_buckets.values())
        self.statisticsTab.trafficLineChart.clear()
        self.statisticsTab.trafficLineChart.plot(x, y, pen=pg.mkPen('#1976D2', width=3))
        self.statisticsTab.trafficLineChart.getAxis('bottom').setTicks([[(i, l) for i, l in enumerate(time_buckets.keys())][::10]])
        # 2. Protocol usage breakdown (bar chart)
        protocol_counts = collections.Counter(row[3].upper() for row in all_rows)
        protocol_order = ['TCP', 'UDP', 'ICMP', 'ARP', 'DNS', 'HTTP', 'OTHER']
        labels = []
        values = []
        color_map = {
            'TCP': '#1976D2',
            'UDP': '#00BCD4',
            'ICMP': '#43A047',
            'ARP': '#FBC02D',
            'DNS': '#8E24AA',
            'HTTP': '#E64A19',
            'OTHER': '#757575',
        }
        for proto in protocol_order:
            count = protocol_counts.get(proto, 0)
            if count > 0:
                labels.append(proto)
                values.append(count)
        for proto, count in protocol_counts.items():
            if proto not in protocol_order and count > 0:
                labels.append(proto)
                values.append(count)
        self.statisticsTab.protocolPieChart.clear()
        bar = pg.BarGraphItem(x=np.array([0, 1]), height=[1, 2], width=0.6, brush='r')
        self.statisticsTab.protocolPieChart.addItem(bar)

        self.statisticsTab.sizeHistogram.clear()
        bar2 = pg.BarGraphItem(x=np.array([0, 1]), height=[2, 1], width=0.6, brush='b')
        self.statisticsTab.sizeHistogram.addItem(bar2)
        # 3. Top talkers (top 10 IPs by packets and bytes)
        talker_stats = collections.Counter()
        talker_bytes = collections.Counter()
        for row in all_rows:
            src = row[1]
            size = int(row[6])
            if src and src != '-':
                talker_stats[src] += 1
                talker_bytes[src] += size
        top_talkers = talker_stats.most_common(10)
        print('Top Talkers:', top_talkers)
        self.statisticsTab.topTalkersTable.setRowCount(0)
        if top_talkers:
            self.statisticsTab.topTalkersTable.setRowCount(len(top_talkers))
            for i, (ip, count) in enumerate(top_talkers):
                bytes_val = talker_bytes[ip]
                self.statisticsTab.topTalkersTable.setItem(i, 0, QTableWidgetItem(ip))
                self.statisticsTab.topTalkersTable.setItem(i, 1, QTableWidgetItem(str(count)))
                self.statisticsTab.topTalkersTable.setItem(i, 2, QTableWidgetItem(str(bytes_val)))
        else:
            self.statisticsTab.topTalkersTable.setRowCount(1)
            self.statisticsTab.topTalkersTable.setItem(0, 0, QTableWidgetItem('No data'))
            self.statisticsTab.topTalkersTable.setItem(0, 1, QTableWidgetItem(''))
            self.statisticsTab.topTalkersTable.setItem(0, 2, QTableWidgetItem(''))
        # 4. Top ports (top 10 by packets and bytes)
        port_stats = collections.Counter()
        port_bytes = collections.Counter()
        for row in all_rows:
            for port in (row[4], row[5]):
                if port and port != '-':
                    port_stats[port] += 1
                    port_bytes[port] += int(row[6])
        top_ports = port_stats.most_common(10)
        print('Top Ports:', top_ports)
        self.statisticsTab.topPortsTable.setRowCount(0)
        if top_ports:
            self.statisticsTab.topPortsTable.setRowCount(len(top_ports))
            for i, (port, count) in enumerate(top_ports):
                bytes_val = port_bytes[port]
                self.statisticsTab.topPortsTable.setItem(i, 0, QTableWidgetItem(str(port)))
                self.statisticsTab.topPortsTable.setItem(i, 1, QTableWidgetItem(str(count)))
                self.statisticsTab.topPortsTable.setItem(i, 2, QTableWidgetItem(str(bytes_val)))
        else:
            self.statisticsTab.topPortsTable.setRowCount(1)
            self.statisticsTab.topPortsTable.setItem(0, 0, QTableWidgetItem('No data'))
            self.statisticsTab.topPortsTable.setItem(0, 1, QTableWidgetItem(''))
            self.statisticsTab.topPortsTable.setItem(0, 2, QTableWidgetItem(''))
        # 5. Packet size distribution (histogram)
        sizes = [int(row[6]) for row in all_rows if row[6] and str(row[6]).isdigit()]
        self.statisticsTab.sizeHistogram.clear()
        if sizes:
            y, x = np.histogram(sizes, bins=20)
            x_centers = (x[:-1] + x[1:]) / 2
            bg = pg.BarGraphItem(x=x_centers, height=y, width=(x[1]-x[0])*0.9, brush='#1976D2', pen='#1976D2')
            self.statisticsTab.sizeHistogram.addItem(bg)
            self.statisticsTab.sizeHistogram.setLabel('left', 'Count')
            self.statisticsTab.sizeHistogram.setLabel('bottom', 'Packet Size (bytes)')
        conn.close()

    def _on_tab_changed(self, index):
        if self.tabs.widget(index) == self.statisticsTab:
            self.update_statistics_tab()

# Entry point
def main():
    app = QApplication(sys.argv)
    window = NetScopeApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main() 