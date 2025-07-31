import sys
import os
import csv
import time
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
import json

# Import enhanced filtering components
try:
    from netscope.backend.packet_sniffer import validate_filter, get_common_filters
    from netscope.backend.advanced_packet_viewer import AdvancedPacketViewer
    ENHANCED_FILTERING = True
except ImportError as e:
    print(f"Warning: Enhanced filtering not available: {e}")
    ENHANCED_FILTERING = False
from PyQt5.QtWidgets import QGraphicsOpacityEffect, QProgressBar
from PyQt5.QtWidgets import QWidget, QHBoxLayout, QSizePolicy
from PyQt5.QtCore import Qt
import pyqtgraph as pg
import numpy as np

class NetScopeApp(QMainWindow):
    def __init__(self):
        super().__init__()
        from PyQt5.QtGui import QFont, QIcon
        self.setWindowTitle('PyGuard – Network Analyzer')
        self.setMinimumSize(1400, 900)
        
        # Import memory monitoring module
        import psutil
        self.psutil_available = True
        
        # High load detection and management
        self.high_load_mode = False
        self.safe_mode = False
        self.packet_count_threshold = 700  # Threshold for high load mode
        self.memory_threshold = 80  # Memory usage percentage threshold
        self.last_crash_file = 'last_crash.txt'
        self.restart_safe_file = 'restart_safe.txt'
        
        # Memory monitoring timer
        self.memory_monitor_timer = QTimer(self)
        self.memory_monitor_timer.timeout.connect(self._monitor_memory_usage)
        self.memory_monitor_timer.start(10000)  # Check every 10 seconds
        
        # Check if we're restarting in safe mode
        if os.path.exists(self.restart_safe_file):
            try:
                with open(self.restart_safe_file, 'r') as f:
                    if f.read().strip() == '1':
                        self.safe_mode = True
                        self.high_load_mode = True
                        print("Restarting in safe mode after crash")
                        
                        # Show notification to user
                        QTimer.singleShot(1000, lambda: QMessageBox.warning(self, 
                            'Safe Mode', 
                            'Application restarted in safe mode after a crash.\n'
                            'Performance optimizations have been enabled automatically.'))
                
                # Remove the file
                os.remove(self.restart_safe_file)
            except Exception as e:
                print(f"Error processing safe mode restart: {e}")
        
        # Check if we had a previous crash
        if os.path.exists(self.last_crash_file) and not self.safe_mode:
            try:
                with open(self.last_crash_file, 'r') as f:
                    crash_data = f.read().strip()
                    if crash_data.startswith('crash:'):
                        # Enable high load mode automatically
                        self.high_load_mode = True
                        print("Previous crash detected, enabling high load mode")
                        
                        # Show notification to user
                        QTimer.singleShot(2000, lambda: QMessageBox.information(self, 
                            'Performance Mode', 
                            'Previous crash detected. Performance optimizations enabled.'))
            except Exception as e:
                print(f"Error reading crash file: {e}")
        
        # Initialize database with enhanced schema
        self._init_enhanced_database()
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
        # Connect filter tab signals
        if hasattr(self.filterTab, 'filterApplied'):
            self.filterTab.filterApplied.connect(self._on_filter_applied)
        # Timer for live updates - use a more reliable timer setup
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_live_table)
        self.update_timer.setSingleShot(False)  # Continuous timer
        self.update_timer.setInterval(1000)     # 1 second interval
        self.update_timer.start()
        
        # Backup timer in case the main timer fails
        self.backup_update_timer = QTimer(self)
        self.backup_update_timer.timeout.connect(self._check_ui_updates)
        self.backup_update_timer.start(5000)  # Check every 5 seconds
        
        # Timer for database optimization (run every 2 minutes)
        self.db_optimize_timer = QTimer(self)
        self.db_optimize_timer.timeout.connect(self._optimize_database)
        self.db_optimize_timer.start(120000)  # 2 minutes in milliseconds
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
        # Disconnect previous connections if any to avoid duplicate popups
        try:
            self.startButton.clicked.disconnect()
        except Exception:
            pass
        try:
            self.stopButton.clicked.disconnect()
        except Exception:
            pass
        try:
            self.clearAllButton.clicked.disconnect()
        except Exception:
            pass
        try:
            self.exportCSVButton.clicked.disconnect()
        except Exception:
            pass
        # Connect only once
        self.startButton.clicked.connect(self.start_capture)
        self.stopButton.clicked.connect(self.stop_capture)
        if hasattr(self.filterTab, 'applyButton'):
            try:
                self.filterTab.applyButton.clicked.disconnect()
            except Exception:
                pass
            self.filterTab.applyButton.clicked.connect(self.apply_filter)
        if hasattr(self.filterTab, 'clearButton'):
            try:
                self.filterTab.clearButton.clicked.disconnect()
            except Exception:
                pass
            self.filterTab.clearButton.clicked.connect(self.clear_filter)
        if hasattr(self.filterTab, 'filterLineEdit'):
            try:
                self.filterTab.filterLineEdit.returnPressed.disconnect()
            except Exception:
                pass
            self.filterTab.filterLineEdit.returnPressed.connect(self.apply_filter)
        self.clearAllButton.clicked.connect(self.clear_all_packets)
        self.exportCSVButton.clicked.connect(self.export_csv)
        if hasattr(self.filterTab, 'filterTable'):
            try:
                self.filterTab.filterTable.cellClicked.disconnect()
            except Exception:
                pass
            self.filterTab.filterTable.cellClicked.connect(self.show_filtered_packet_details)
        if hasattr(self.liveCaptureTab, 'packetSelected'):
            try:
                self.liveCaptureTab.packetSelected.disconnect()
            except Exception:
                pass
            self.liveCaptureTab.packetSelected.connect(self._on_packet_selected)

    def _check_high_load(self):
        """Check if we're in a high load situation and adjust settings accordingly"""
        try:
            conn = sqlite3.connect('packets.db')
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM packets')
            count = cursor.fetchone()[0]
            conn.close()
            
            # Check if we're approaching the threshold
            if count > self.packet_count_threshold:
                if not self.high_load_mode:
                    print(f"High packet count detected ({count}), enabling high load mode")
                    self.high_load_mode = True
                    
                    # Adjust UI update frequency
                    self.update_timer.stop()
                    self.update_timer.start(2000)  # Reduce UI updates to every 2 seconds
                    
                    # Show notification to user
                    QMessageBox.information(self, 'High Load Mode', 
                                           'High packet count detected. Enabling performance optimizations.')
                    
                    # Record the high load event
                    try:
                        with open(self.last_crash_file, 'w') as f:
                            f.write(f'high_load:{count}')
                    except Exception as e:
                        print(f"Error writing high load file: {e}")
            
            # If packet count is low again, disable high load mode
            elif self.high_load_mode and count < (self.packet_count_threshold / 2):
                print(f"Packet count reduced ({count}), disabling high load mode")
                self.high_load_mode = False
                
                # Restore normal UI update frequency
                self.update_timer.stop()
                self.update_timer.start(1000)
                
        except Exception as e:
            print(f"Error checking high load: {e}")
    
    def start_capture(self):
        try:
            # Clean up old packets before starting a new capture
            self._cleanup_old_packets()
            
            # Check for high load situation
            self._check_high_load()
            
            # Make sure we have a valid interface
            interface = self._auto_select_interface()
            if not interface:
                QMessageBox.warning(self, 'Interface Error', 'No valid network interface found for capture.')
                return
                
            print(f"Starting capture on interface: {interface}")
            
            # Get BPF filter from filter tab
            if hasattr(self.filterTab, 'get_current_bpf_filter'):
                bpf_filter = self.filterTab.get_current_bpf_filter()
            else:
                bpf_filter = getattr(self.filterTab, 'filterLineEdit', QLineEdit()).text()
            
            # Validate filter if enhanced filtering is available
            if ENHANCED_FILTERING and bpf_filter:
                is_valid, message = validate_filter(bpf_filter)
                if not is_valid:
                    QMessageBox.warning(self, 'Invalid Filter', f'BPF filter validation failed:\n{message}')
                    return
            
            # Reset UI update tracking
            self._last_ui_update_time = time.time()
            self._packet_count_cache = 0
            self._consecutive_errors = 0
            
            # Configure capture manager based on load mode
            if self.high_load_mode:
                # Use enhanced mode with optimized settings for high load
                self.capture_manager.start(
                    interface=interface, 
                    bpf_filter=bpf_filter,
                    enhanced_mode=True,
                    sample_rate=3  # Sample every 3rd packet
                )
                print("Starting capture in high load mode with sampling")
            else:
                # Normal mode
                self.capture_manager.start(interface=interface, bpf_filter=bpf_filter)
                print("Starting capture in normal mode")
                
            # Force an immediate UI update to show we're capturing
            self.update_live_table()
            
            # Update dashboard with active filter
            try:
                if hasattr(self.dashboardTab, 'set_active_bpf_filter'):
                    self.dashboardTab.set_active_bpf_filter(bpf_filter)
                elif hasattr(self.dashboardTab, 'activeFilterValue'):
                    self.dashboardTab.activeFilterValue.setText(bpf_filter or "None")
            except Exception as e:
                print(f"Error updating dashboard filter: {e}")
                
            # Disable BPF filter editing during capture
            if hasattr(self.filterTab, 'filterLineEdit'):
                self.filterTab.filterLineEdit.setReadOnly(True)
            if hasattr(self.filterTab, 'applyButton'):
                self.filterTab.applyButton.setEnabled(False)
            if hasattr(self.filterTab, 'clearButton'):
                self.filterTab.clearButton.setEnabled(False)
                
            # Update status message
            filter_msg = f" with filter: {bpf_filter}" if bpf_filter else ""
            QMessageBox.information(self, 'Capture Started', f'Capturing on {interface}{filter_msg}')
            
            # Make sure the update timer is running
            if not self.update_timer.isActive():
                print("Update timer was not active. Starting it...")
                self.update_timer.start()
                
        except Exception as e:
            print(f"Error starting capture: {e}")
            QMessageBox.critical(self, 'Capture Error', f'Failed to start packet capture: {str(e)}')
            
            # Try to recover
            try:
                self.capture_manager.stop()
            except:
                pass

    def stop_capture(self):
        self.capture_manager.stop()
        QMessageBox.information(self, 'Capture Stopped', 'Packet capture stopped.')
        # Re-enable BPF filter editing after capture
        if hasattr(self.filterTab, 'filterLineEdit'):
            self.filterTab.filterLineEdit.setReadOnly(False)
        if hasattr(self.filterTab, 'applyButton'):
            self.filterTab.applyButton.setEnabled(True)
        if hasattr(self.filterTab, 'clearButton'):
            self.filterTab.clearButton.setEnabled(True)

    def apply_filter(self):
        """Apply filter - enhanced version with backward compatibility"""
        try:
            # Check if enhanced filtering is available
            if hasattr(self.filterTab, 'get_current_bpf_filter') and hasattr(self.filterTab, 'get_current_display_filter'):
                bpf_filter = self.filterTab.get_current_bpf_filter()
                display_filter = self.filterTab.get_current_display_filter()
                
                # Emit the enhanced filter signal
                if hasattr(self.filterTab, 'filterApplied'):
                    self.filterTab.filterApplied.emit(bpf_filter, display_filter)
                else:
                    # Fallback to manual update
                    self.update_live_table()
            else:
                # Fallback for old filter system
                self.update_live_table()
                
        except Exception as e:
            print(f"Error applying filter: {e}")
            self.update_live_table()

    def clear_filter(self):
        """Clear filter - enhanced version with backward compatibility"""
        try:
            # Check if enhanced filtering is available
            if hasattr(self.filterTab, 'set_bpf_filter') and hasattr(self.filterTab, 'set_display_filter'):
                self.filterTab.set_bpf_filter("")
                self.filterTab.set_display_filter("")
            elif hasattr(self.filterTab, 'filterLineEdit'):
                # Fallback for old filter system
                self.filterTab.filterLineEdit.clear()
            
            # Update tables
            self.update_live_table()
            
        except Exception as e:
            print(f"Error clearing filter: {e}")
            if hasattr(self.filterTab, 'filterLineEdit'):
                self.filterTab.filterLineEdit.clear()
            self.update_live_table()

    def _parse_filter(self, filter_str):
        # Enhanced Wireshark-like filter parser
        # Supports: src_ip, dst_ip, src_port, dst_port, protocol, size, timestamp
        # Operators: ==, !=, >, <, >=, <=, contains
        # Logical: and, or, not, parentheses
        if not filter_str.strip():
            return None, []
        # Map Wireshark/common field names to DB columns
        field_map = {
            'src_ip': 'src_ip',
            'dst_ip': 'dst_ip',
            'src_port': 'src_port',
            'dst_port': 'dst_port',
            'protocol': 'protocol',
            'size': 'size',
            'timestamp': 'timestamp',
        }
        # Tokenize (very basic, not a full parser)
        import re
        tokens = re.findall(r'\w+|==|!=|>=|<=|>|<|\(|\)|contains|and|or|not|"[^"]*"|\'[^\']*\'|\S', filter_str)
        sql = ''
        params = []
        i = 0
        def parse_expr():
            nonlocal i
            expr = ''
            while i < len(tokens):
                token = tokens[i]
                if token == '(': 
                    i += 1
                    subexpr = parse_expr()
                    expr += f'({subexpr})'
                elif token == ')':
                    i += 1
                    break
                elif token.lower() == 'and':
                    expr += ' AND '
                    i += 1
                elif token.lower() == 'or':
                    expr += ' OR '
                    i += 1
                elif token.lower() == 'not':
                    expr += ' NOT '
                    i += 1
                elif token in field_map:
                    field = field_map[token]
                    i += 1
                    if i < len(tokens):
                        op = tokens[i]
                        i += 1
                        if op in ['==', '!=', '>', '<', '>=', '<=']:
                            if i < len(tokens):
                                value = tokens[i]
                                i += 1
                                if value.startswith('"') and value.endswith('"') or value.startswith("'") and value.endswith("'"):
                                    value = value[1:-1]
                                expr += f'{field} {op.replace("==", "=")} ?'
                                params.append(value)
                            else:
                                expr += f'{field} {op.replace("==", "=")} ?'
                                params.append('')
                        elif op == 'contains':
                            if i < len(tokens):
                                value = tokens[i]
                                i += 1
                                if value.startswith('"') and value.endswith('"') or value.startswith("'") and value.endswith("'"):
                                    value = value[1:-1]
                                expr += f'{field} LIKE ?'
                                params.append(f'%{value}%')
                            else:
                                expr += f'{field} LIKE ?'
                                params.append('%%')
                        else:
                            # Unknown operator, skip
                            pass
                    else:
                        # Field with no operator, skip
                        pass
                else:
                    # Unknown token, skip
                    i += 1
            return expr
        sql = parse_expr()
        if sql:
            return sql, params
        return None, []

    def update_live_table(self):
        """Update live capture table - enhanced version with adaptive refresh rate and improved reliability"""
        try:
            # Record the update attempt time for the backup timer
            self._last_ui_update_time = time.time()
            
            # Check if we're in a high-load situation
            if not hasattr(self, '_packet_count_cache'):
                self._packet_count_cache = 0
                self._last_update_time = time.time()
                self._update_skip_counter = 0
                self._adaptive_update_interval = 1  # Start with normal updates
                self._consecutive_errors = 0  # Track consecutive errors
            
            # Get current packet count with better error handling
            try:
                conn = sqlite3.connect('packets.db', timeout=5.0)  # Increase timeout for busy database
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM packets')
                current_count = cursor.fetchone()[0]
                conn.close()
                
                # Reset error counter on successful database access
                self._consecutive_errors = 0
            except Exception as e:
                print(f"Error getting packet count: {e}")
                current_count = self._packet_count_cache  # Use last known count
                self._consecutive_errors += 1
                
                # If we have too many consecutive errors, try to recover
                if self._consecutive_errors > 3:
                    print("Multiple consecutive database errors. Attempting recovery...")
                    try:
                        # Force close any open connections
                        import gc
                        gc.collect()
                        
                        # Wait a moment
                        time.sleep(0.5)
                        
                        # Try a simple query to reset the connection
                        test_conn = sqlite3.connect('packets.db', timeout=10.0)
                        test_conn.execute('SELECT 1')
                        test_conn.close()
                        
                        print("Database connection recovery successful")
                        self._consecutive_errors = 0
                    except Exception as recovery_error:
                        print(f"Database recovery failed: {recovery_error}")
            
            # Determine if we're in a high-load situation
            time_diff = max(0.1, time.time() - self._last_update_time)
            packet_rate = (current_count - self._packet_count_cache) / time_diff
            self._packet_count_cache = current_count
            self._last_update_time = time.time()
            
            # Log packet rate periodically
            if hasattr(self, '_rate_log_counter'):
                self._rate_log_counter += 1
            else:
                self._rate_log_counter = 0
                
            if self._rate_log_counter % 10 == 0:  # Log every 10 updates
                print(f"Current packet rate: {packet_rate:.1f} packets/second, Total: {current_count}")
            
            # Adjust update frequency based on packet rate and total count
            if current_count > 700:  # High load threshold
                self._adaptive_update_interval = 5  # Update every 5th call
            elif current_count > 500:  # Medium load threshold
                self._adaptive_update_interval = 3  # Update every 3rd call
            elif packet_rate > 50:  # High packet rate
                self._adaptive_update_interval = 2  # Update every 2nd call
            else:
                self._adaptive_update_interval = 1  # Normal updates
            
            # Skip updates based on adaptive interval
            self._update_skip_counter += 1
            if self._update_skip_counter % self._adaptive_update_interval != 0:
                return
            
            # Reset counter after update
            self._update_skip_counter = 0
            
            # Use enhanced live capture refresh if available
            if hasattr(self.liveCaptureTab, 'refresh_packets'):
                try:
                    self.liveCaptureTab.refresh_packets()
                except Exception as e:
                    print(f"Error in enhanced refresh: {e}")
                    # Fall back to basic refresh method
                    self._basic_table_refresh()
            else:
                # Use basic refresh method
                self._basic_table_refresh()
            
            # Update filter tab if enhanced filtering is available
            try:
                if hasattr(self.filterTab, '_refresh_filtered_table'):
                    self.filterTab._refresh_filtered_table()
                else:
                    # Fallback to old filter method
                    self._update_old_filter_table()
            except Exception as e:
                print(f"Error updating filter table: {e}")
                
        except Exception as e:
            print(f"Error updating live table: {e}")
            # Log the error to help with debugging
            try:
                with open('ui_errors.log', 'a') as f:
                    f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Error updating live table: {e}\n")
            except:
                pass
            
            # Try to recover by forcing garbage collection
            try:
                import gc
                gc.collect()
            except:
                pass
    
    def _basic_table_refresh(self):
        """Basic table refresh method as a fallback"""
        try:
            conn = sqlite3.connect('packets.db', timeout=5.0)
            cursor = conn.cursor()
            
            # Use a more efficient query with LIMIT
            cursor.execute('''
                SELECT id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size 
                FROM packets 
                ORDER BY id DESC 
                LIMIT 500
            ''')
            
            all_rows = cursor.fetchall()
            
            # Disable UI updates during table population
            self.liveCaptureTab.packetTable.setUpdatesEnabled(False)
            
            # Set row count once
            self.liveCaptureTab.packetTable.setRowCount(len(all_rows))
            
            # Populate table
            for row_idx, row in enumerate(all_rows):
                for col_idx, value in enumerate(row):
                    self.liveCaptureTab.packetTable.setItem(row_idx, col_idx, self.make_table_item(str(value)))
            
            # Re-enable UI updates
            self.liveCaptureTab.packetTable.setUpdatesEnabled(True)
            
            # Update packet count in status bar
            if hasattr(self.liveCaptureTab, 'packetCountLabel'):
                self.liveCaptureTab.packetCountLabel.setText(f"Packets: {self._packet_count_cache}")
                
            conn.close()
        except Exception as e:
            print(f"Error in basic table refresh: {e}")
            
    def _update_old_filter_table(self):
        """Fallback method for old filter table update"""
        try:
            conn = sqlite3.connect('packets.db')
            cursor = conn.cursor()
            
            # Get filter text from appropriate widget
            filter_str = ""
            if hasattr(self.filterTab, 'filterLineEdit'):
                filter_str = self.filterTab.filterLineEdit.text().strip()
            
            sql, params = self._parse_filter(filter_str)
            if sql:
                query = f'SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size FROM packets WHERE {sql} ORDER BY id DESC LIMIT 500'
                cursor.execute(query, params)
                filter_rows = cursor.fetchall()
            else:
                cursor.execute('SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size FROM packets ORDER BY id DESC LIMIT 500')
                filter_rows = cursor.fetchall()
                
            if hasattr(self.filterTab, 'filterTable'):
                self.filterTab.filterTable.setRowCount(len(filter_rows))
                for row_idx, row in enumerate(filter_rows):
                    for col_idx, value in enumerate(row):
                        self.filterTab.filterTable.setItem(row_idx, col_idx, self.make_table_item(str(value)))
            
            conn.close()
            
        except Exception as e:
            print(f"Error updating old filter table: {e}")
    
    def _on_packet_selected(self, packet_data):
        """Handle packet selection from live capture"""
        try:
            if hasattr(self.packetDetailsTab, 'show_packet_details'):
                self.packetDetailsTab.show_packet_details(packet_data)
            # Switch to packet details tab
            for i in range(self.tabs.count()):
                if self.tabs.widget(i) == self.packetDetailsTab:
                    self.tabs.setCurrentIndex(i)
                    break
        except Exception as e:
            print(f"Error handling packet selection: {e}")
        # Update the active filter value in the dashboard
        self.dashboardTab.activeFilterValue.setText(active_filter)
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
            try:
                conn = sqlite3.connect('packets.db')
                cursor = conn.cursor()
                cursor.execute('DELETE FROM packets')
                conn.commit()
                conn.close()
                
                # Clear UI tables
                if hasattr(self.liveCaptureTab, 'clear_packets'):
                    self.liveCaptureTab.clear_packets()
                else:
                    self.liveCaptureTab.packetTable.setRowCount(0)
                
                if hasattr(self.filterTab, 'filterTable'):
                    self.filterTab.filterTable.setRowCount(0)
                
                # Update other tables
                self.update_live_table()
                
                QMessageBox.information(self, 'Cleared', 'All packets have been deleted.')
                
            except Exception as e:
                QMessageBox.warning(self, 'Error', f'Failed to clear packets: {str(e)}')

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Export Packets as CSV', '', 'CSV Files (*.csv)')
        if not path:
            return
        conn = sqlite3.connect('packets.db')
        cursor = conn.cursor()
        # Limit export to most recent 1000 packets for performance
        cursor.execute('SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size FROM packets ORDER BY id DESC LIMIT 1000')
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
            title = QLabel('👋 Welcome to PyGuard!')
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

    def show_packet_details(self, row, col=None):
        """Show packet details - enhanced version with backward compatibility"""
        details = {}
        
        try:
            # Handle direct packet data (from enhanced system)
            if isinstance(row, dict):
                packet_data = row
                details = packet_data
            else:
                # Handle old table row selection
                table = self.liveCaptureTab.packetTable
                
                # Check if we have enhanced table with packet data stored
                if table.item(row, 0) and hasattr(table.item(row, 0), 'data'):
                    packet_data = table.item(row, 0).data(Qt.UserRole)
                    if packet_data:
                        details = packet_data
                    else:
                        # Fallback to database lookup
                        details = self._get_packet_details_from_db(row)
                else:
                    # Fallback to database lookup
                    details = self._get_packet_details_from_db(row)
                    
        except Exception as e:
            print(f"Error getting packet details: {e}")
            details = self._get_packet_details_from_db(row)
        
        # Display the packet details using the new method if available
        if hasattr(self.packetDetailsTab, 'show_packet_details'):
            self.packetDetailsTab.show_packet_details(details)
            self.tabs.setCurrentWidget(self.packetDetailsTab)
        else:
            # Fallback to old method
            self._build_packet_details_display(details)
    
    def _get_packet_details_from_db(self, row):
        """Fallback method to get packet details from database"""
        try:
            table = self.liveCaptureTab.packetTable
            timestamp = table.item(row, 1).text() if table.item(row, 1) else ''  # Column 1 is timestamp in enhanced table
            src_ip = table.item(row, 2).text() if table.item(row, 2) else ''     # Column 2 is src_ip in enhanced table
            
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
            return details
            
        except Exception as e:
            print(f"Error getting packet details from DB: {e}")
            return {}
    
    def _build_packet_details_display(self, details):
        """Build the packet details display from packet data"""
        # Build protocol tables with expanded field lists
        protocol_fields = [
            ('Ethernet', ['eth_src', 'eth_dst', 'eth_type']),
            ('IP', ['ip_version', 'ip_ihl', 'ip_tos', 'ip_len', 'ip_id', 'ip_flags', 'ip_frag', 'ip_ttl', 'ip_proto', 'ip_chksum', 'ip_options']),
            ('TCP', ['tcp_seq', 'tcp_ack', 'tcp_dataofs', 'tcp_reserved', 'tcp_flags_raw', 'tcp_window', 'tcp_chksum', 'tcp_urgptr', 'tcp_options']),
            ('UDP', ['udp_len', 'udp_chksum']),
            ('DNS', ['dns_id', 'dns_qr', 'dns_opcode', 'dns_aa', 'dns_tc', 'dns_rd', 'dns_ra', 'dns_z', 'dns_rcode', 'dns_qdcount', 'dns_ancount', 'dns_nscount', 'dns_arcount', 'dns_qd', 'dns_an', 'dns_qname', 'dns_qtype', 'dns_qclass', 'dns_type', 'dns_an_name', 'dns_an_type', 'dns_an_rdata', 'dns_an_ttl']),
            ('ICMP', ['icmp_type', 'icmp_code', 'icmp_chksum', 'icmp_id', 'icmp_seq', 'icmp_type_name']),
            ('ARP', ['arp_hwtype', 'arp_ptype', 'arp_hwlen', 'arp_plen', 'arp_op', 'arp_op_name', 'arp_hwsrc', 'arp_psrc', 'arp_hwdst', 'arp_pdst']),
            ('HTTP', ['http_data', 'http_method', 'http_uri', 'http_version', 'http_headers']),
        ]
        
        first_present = None
        for proto, fields in protocol_fields:
            field_dict = {f: details[f] for f in fields if f in details}
            
            # Add TCP flags to TCP table if present
            if proto == 'TCP' and 'tcp_flags' in details and isinstance(details['tcp_flags'], dict):
                for flag, value in details['tcp_flags'].items():
                    field_dict[f'Flag {flag}'] = value
            
            self.packetDetailsTab.populate_protocol_table(proto, field_dict)
            if field_dict and first_present is None:
                first_present = proto
        # Show raw/hex payload if available
        hex_dump = details.get('raw', '')
        if hex_dump:
            try:
                hex_bytes = bytes.fromhex(hex_dump)
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
        # Switch to Packet Details tab and show the first present protocol's table
        if first_present:
            idx = list(self.packetDetailsTab.protocolTables.keys()).index(first_present) + 1  # +1 for tree view tab
            self.packetDetailsTab.detailsTabWidget.setCurrentIndex(idx)
        else:
            self.packetDetailsTab.detailsTabWidget.setCurrentIndex(0)
        self.tabs.setCurrentWidget(self.packetDetailsTab)

    def show_filtered_packet_details(self, row, col):
        table = self.filterTab.filterTable
        timestamp = table.item(row, 0).text() if table.item(row, 0) else ''
        src_ip = table.item(row, 1).text() if table.item(row, 1) else ''
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
        
        # Display the packet details using the new method if available
        if hasattr(self.packetDetailsTab, 'show_packet_details'):
            self.packetDetailsTab.show_packet_details(details)
            self.tabs.setCurrentWidget(self.packetDetailsTab)
        else:
            # Fallback to old method
            self.packetDetailsTab.clear_details()
            self.packetDetailsTab.populate_protocol_tree(details)
            
            # Use the same expanded field lists as in _build_packet_details_display
            protocol_fields = [
                ('Ethernet', ['eth_src', 'eth_dst', 'eth_type']),
                ('IP', ['ip_version', 'ip_ihl', 'ip_tos', 'ip_len', 'ip_id', 'ip_flags', 'ip_frag', 'ip_ttl', 'ip_proto', 'ip_chksum', 'ip_options']),
                ('TCP', ['tcp_seq', 'tcp_ack', 'tcp_dataofs', 'tcp_reserved', 'tcp_flags_raw', 'tcp_window', 'tcp_chksum', 'tcp_urgptr', 'tcp_options']),
                ('UDP', ['udp_len', 'udp_chksum']),
                ('DNS', ['dns_id', 'dns_qr', 'dns_opcode', 'dns_aa', 'dns_tc', 'dns_rd', 'dns_ra', 'dns_z', 'dns_rcode', 'dns_qdcount', 'dns_ancount', 'dns_nscount', 'dns_arcount', 'dns_qd', 'dns_an', 'dns_qname', 'dns_qtype', 'dns_qclass', 'dns_type', 'dns_an_name', 'dns_an_type', 'dns_an_rdata', 'dns_an_ttl']),
                ('ICMP', ['icmp_type', 'icmp_code', 'icmp_chksum', 'icmp_id', 'icmp_seq', 'icmp_type_name']),
                ('ARP', ['arp_hwtype', 'arp_ptype', 'arp_hwlen', 'arp_plen', 'arp_op', 'arp_op_name', 'arp_hwsrc', 'arp_psrc', 'arp_hwdst', 'arp_pdst']),
                ('HTTP', ['http_data', 'http_method', 'http_uri', 'http_version', 'http_headers']),
            ]
            
            first_present = None
            for proto, fields in protocol_fields:
                field_dict = {f: details[f] for f in fields if f in details}
                
                # Add TCP flags to TCP table if present
                if proto == 'TCP' and 'tcp_flags' in details and isinstance(details['tcp_flags'], dict):
                    for flag, value in details['tcp_flags'].items():
                        field_dict[f'Flag {flag}'] = value
                
                self.packetDetailsTab.populate_protocol_table(proto, field_dict)
                if field_dict and first_present is None:
                    first_present = proto
        hex_dump = details.get('raw', '')
        if hex_dump:
            try:
                hex_bytes = bytes.fromhex(hex_dump)
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
        if first_present:
            idx = list(self.packetDetailsTab.protocolTables.keys()).index(first_present) + 1
            self.packetDetailsTab.detailsTabWidget.setCurrentIndex(idx)
        else:
            self.packetDetailsTab.detailsTabWidget.setCurrentIndex(0)
        self.tabs.setCurrentWidget(self.packetDetailsTab)

    def show_filtered_packet_details(self, row, col):
        # Get packet data from the selected row in the filter table
        table = self.filterTab.filterTable
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
        import sqlite3, collections
        conn = sqlite3.connect('packets.db')
        cursor = conn.cursor()
        cursor.execute('SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size FROM packets ORDER BY id DESC LIMIT 1000')
        all_rows = cursor.fetchall()
        # Top Talkers
        talker_stats = collections.Counter()
        talker_bytes = collections.Counter()
        for row in all_rows:
            src = row[1]
            size = int(row[6])
            if src and src != '-':
                talker_stats[src] += 1
                talker_bytes[src] += size
        top_talkers = [
            {'ip': ip, 'packets': count, 'bytes': talker_bytes[ip]}
            for ip, count in talker_stats.most_common(10)
        ]
        # Top Ports
        port_stats = collections.Counter()
        port_bytes = collections.Counter()
        for row in all_rows:
            for port in (row[4], row[5]):
                if port and port != '-':
                    port_stats[port] += 1
                    port_bytes[port] += int(row[6])
        top_ports = [
            {'port': port, 'packets': count, 'bytes': port_bytes[port]}
            for port, count in port_stats.most_common(10)
        ]
        # Protocol Usage
        protocol_stats = collections.Counter(row[3].upper() for row in all_rows)
        total_packets = sum(protocol_stats.values())
        protocol_bytes = collections.Counter()
        for row in all_rows:
            proto = row[3].upper()
            protocol_bytes[proto] += int(row[6])
        protocol_usage = []
        for proto, count in protocol_stats.items():
            percent = (count / total_packets * 100) if total_packets else 0
            protocol_usage.append({
                'protocol': proto,
                'packets': count,
                'bytes': protocol_bytes[proto],
                'percent': percent
            })
        # Sort protocol_usage by packets descending
        protocol_usage.sort(key=lambda x: x['packets'], reverse=True)
        # Call the new update_statistics method
        self.statisticsTab.update_statistics({
            'top_talkers': top_talkers,
            'top_ports': top_ports,
            'protocol_usage': protocol_usage
        })
        conn.close()

    def _on_tab_changed(self, index):
        if self.tabs.widget(index) == self.statisticsTab:
            self.update_statistics_tab()
            
    def _check_ui_updates(self):
        """Backup function to ensure UI updates are happening"""
        try:
            # Check when the last UI update happened
            current_time = time.time()
            if not hasattr(self, '_last_ui_update_time'):
                self._last_ui_update_time = current_time
                return
                
            # If it's been more than 10 seconds since the last update, force an update
            if current_time - self._last_ui_update_time > 10:
                print("UI updates appear to be stalled. Forcing update...")
                self.update_live_table()
                
                # Restart the main timer if it seems to have stopped
                if not self.update_timer.isActive():
                    print("Main update timer is not active. Restarting...")
                    self.update_timer.start()
        except Exception as e:
            print(f"Error in backup UI update check: {e}")
    
    def _monitor_memory_usage(self):
        """Monitor memory usage and take action if it gets too high"""
        try:
            if not hasattr(self, 'psutil_available') or not self.psutil_available:
                return
                
            import psutil
            memory_percent = psutil.virtual_memory().percent
            
            # If memory usage is above threshold, take action
            if memory_percent > self.memory_threshold:
                print(f"High memory usage detected: {memory_percent}%")
                
                # If we're capturing packets, stop the capture
                if self.capture_manager.running:
                    print("Stopping packet capture due to high memory usage")
                    self.stop_capture()
                    
                    # Show notification to user
                    QMessageBox.warning(self, 
                        'High Memory Usage', 
                        f'Memory usage is high ({memory_percent}%). Packet capture has been stopped to prevent crashes.')
                
                # Force garbage collection
                import gc
                gc.collect()
                
                # Enable high load mode
                if not self.high_load_mode:
                    self.high_load_mode = True
                    print("Enabling high load mode due to high memory usage")
        except Exception as e:
            print(f"Error monitoring memory usage: {e}")

# Entry point
    def _cleanup_old_packets(self):
        """Clean up old packets to prevent database growth"""
        try:
            conn = sqlite3.connect('packets.db')
            cursor = conn.cursor()
            
            # Get total packet count
            cursor.execute('SELECT COUNT(*) FROM packets')
            total_count = cursor.fetchone()[0]
            
            # If we have more than 1000 packets, delete the oldest ones
            if total_count > 1000:
                # Keep the 1000 most recent packets
                cursor.execute('DELETE FROM packets WHERE id NOT IN (SELECT id FROM packets ORDER BY id DESC LIMIT 1000)')
                deleted_count = conn.total_changes
                print(f"Cleaned up {deleted_count} old packets")
                
                # Perform a vacuum operation if we deleted a significant number of packets
                if deleted_count > 100:
                    print("Performing database vacuum to optimize storage...")
                    cursor.execute('VACUUM')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error cleaning up old packets: {e}")
            
    def _optimize_database(self):
        """Perform database optimization operations"""
        try:
            conn = sqlite3.connect('packets.db')
            cursor = conn.cursor()
            
            # Check database size
            cursor.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
            db_size = cursor.fetchone()[0]
            db_size_mb = db_size / (1024 * 1024)
            
            # If database is larger than 50MB, be more aggressive with cleanup
            if db_size_mb > 50:
                print(f"Database size is large ({db_size_mb:.2f} MB). Performing aggressive cleanup...")
                # Keep only the 500 most recent packets
                cursor.execute('DELETE FROM packets WHERE id NOT IN (SELECT id FROM packets ORDER BY id DESC LIMIT 500)')
                deleted_count = conn.total_changes
                print(f"Aggressively cleaned up {deleted_count} old packets")
                
                # Vacuum the database to reclaim space
                cursor.execute('VACUUM')
            else:
                # Run ANALYZE to update statistics
                cursor.execute('ANALYZE')
            
            # Run integrity check
            cursor.execute('PRAGMA integrity_check')
            integrity_result = cursor.fetchone()[0]
            if integrity_result != 'ok':
                print(f"Database integrity check failed: {integrity_result}")
                
                # Try to recover by recreating indexes
                try:
                    print("Attempting to recover by recreating indexes...")
                    cursor.execute('REINDEX')
                except Exception as e:
                    print(f"Index recreation failed: {e}")
            
            # Optimize database settings
            cursor.execute('PRAGMA temp_store = MEMORY')  # Store temp tables in memory
            cursor.execute('PRAGMA mmap_size = 30000000')  # Use memory-mapped I/O (about 30MB)
            
            conn.close()
            return integrity_result == 'ok'
        except Exception as e:
            print(f"Error optimizing database: {e}")
            return False
    
    def _init_enhanced_database(self):
        """Initialize database with enhanced schema"""
        try:
            conn = sqlite3.connect('packets.db')
            cursor = conn.cursor()
            
            # Create enhanced table schema with indexes
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    size INTEGER NOT NULL,
                    details TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for better query performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_ip ON packets(src_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_dst_ip ON packets(dst_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_protocol ON packets(protocol)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_port ON packets(src_port)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_dst_port ON packets(dst_port)')
            
            # Clear existing packets on startup
            cursor.execute('DELETE FROM packets')
            
            conn.commit()
            conn.close()
            print("Enhanced database initialized successfully")
            
        except Exception as e:
            print(f"Error initializing database: {e}")
            # Fallback to basic initialization
            conn = sqlite3.connect('packets.db')
            cursor = conn.cursor()
            cursor.execute('DELETE FROM packets')
            conn.commit()
            conn.close()
            
    def _on_filter_applied(self, bpf_filter, display_filter):
        """Handle filter application from filter tab"""
        if bpf_filter:
            # BPF filter applied - restart capture with new filter
            if self.capture_manager and hasattr(self.capture_manager, 'is_running') and self.capture_manager.is_running:
                self.stop_capture()
                QMessageBox.information(self, 'Filter Applied', 
                    'Capture stopped. Click Start to begin capturing with new BPF filter.')
        
        if display_filter:
            # Display filter applied - refresh filter table
            self._refresh_display_filter()
            
    def _refresh_display_filter(self):
        """Refresh display filter results"""
        try:
            if hasattr(self.filterTab, '_refresh_filtered_table'):
                self.filterTab._refresh_filtered_table()
        except Exception as e:
            print(f"Error refreshing display filter: {e}")

def record_crash(e):
    """Record crash information to a file"""
    try:
        with open('last_crash.txt', 'w') as f:
            f.write(f'crash:{str(e)}')
    except Exception as write_error:
        print(f"Error writing crash file: {write_error}")

def exception_hook(exctype, value, traceback):
    """Global exception handler to record crashes"""
    # Call the default handler
    sys.__excepthook__(exctype, value, traceback)
    
    # Record the crash
    record_crash(value)

def main():
    # Set up global exception handler
    sys.excepthook = exception_hook
    
    try:
        app = QApplication(sys.argv)
        window = NetScopeApp()
        window.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"Critical error: {e}")
        record_crash(e)
        # Try to restart in safe mode
        try:
            # Write to a file that will be read on next startup
            with open('restart_safe.txt', 'w') as f:
                f.write('1')
            # Restart the application
            os.execl(sys.executable, sys.executable, *sys.argv)
        except Exception as restart_error:
            print(f"Failed to restart: {restart_error}")

if __name__ == '__main__':
    main() 