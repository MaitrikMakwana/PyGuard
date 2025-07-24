import sys
import os
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QComboBox, 
                            QPushButton, QLabel, QTableWidget, QSizePolicy, QTextEdit, 
                            QSplitter, QMessageBox, QTableWidgetItem, QToolButton, QFrame)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QIcon, QFont, QPixmap

# Add the backend directory to Python path
backend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'netscope', 'backend')
sys.path.insert(0, backend_dir)

try:
    from packet_sniffer import validate_filter, get_common_filters, get_filter_help
    from advanced_packet_viewer import AdvancedPacketViewer, get_display_filter_help
except ImportError as e:
    print(f"Warning: Could not import enhanced filtering: {e}")
    validate_filter = None
    get_common_filters = None
    get_filter_help = None

class FilterTab(QWidget):
    # Signal emitted when filter is applied
    filterApplied = pyqtSignal(str, str)  # (bpf_filter, display_filter)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(32, 32, 32, 32)
        main_layout.setSpacing(24)

        # Action Bar (fixed at top)
        action_bar = QHBoxLayout()
        action_bar.setSpacing(16)
        filter_icon = QLabel()
        filter_icon.setPixmap(QPixmap(':/icons/filter.png').scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        filter_icon.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        action_bar.addWidget(filter_icon)
        section_title = QLabel('Packet Filtering')
        section_title.setFont(QFont('Segoe UI', 22, QFont.Bold))
        section_title.setStyleSheet('color: #00BCD4;')
        action_bar.addWidget(section_title)
        action_bar.addStretch(1)
        main_layout.addLayout(action_bar)

        # Splitter for BPF and Display filter sections
        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)

        # BPF Filter Section (in a card)
        bpf_card = QFrame()
        bpf_card.setFrameShape(QFrame.StyledPanel)
        bpf_card.setFrameShadow(QFrame.Raised)
        bpf_card.setStyleSheet('''
            QFrame {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 24px;
                border: 1.5px solid rgba(255,255,255,0.10);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.10);
            }
        ''')
        bpf_layout = QVBoxLayout(bpf_card)
        bpf_layout.setContentsMargins(24, 24, 24, 24)
        bpf_layout.setSpacing(16)
        bpf_header = QHBoxLayout()
        bpf_icon = QLabel()
        bpf_icon.setPixmap(QPixmap(':/icons/bpf.png').scaled(24, 24, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        bpf_header.addWidget(bpf_icon)
        bpf_title = QLabel('🔍 BPF Capture Filters (Real-time)')
        bpf_title.setFont(QFont('Segoe UI', 18, QFont.Bold))
        bpf_title.setStyleSheet('color: #00BCD4;')
        bpf_header.addWidget(bpf_title)
        bpf_header.addStretch(1)
        bpf_layout.addLayout(bpf_header)
        filter_row = QHBoxLayout()
        filter_row.setSpacing(16)
        self.filterLineEdit = QLineEdit()
        self.filterLineEdit.setPlaceholderText('tcp and (port 80 or port 443)')
        self.filterLineEdit.setObjectName('filterLineEdit')
        self.filterLineEdit.setStyleSheet('''
            QLineEdit {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 16px;
                border: 1.5px solid rgba(255,255,255,0.10);
                color: #E0E0E0;
                font-size: 18px;
                padding: 10px 18px;
            }
            QLineEdit:focus {
                border: 2px solid #00BCD4;
                background: rgba(44, 44, 64, 0.75);
            }
        ''')
        self.presetCombo = QComboBox()
        self.presetCombo.setObjectName('presetCombo')
        self.presetCombo.setStyleSheet('''
            QComboBox {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 16px;
                border: 1.5px solid rgba(255,255,255,0.10);
                color: #E0E0E0;
                font-size: 18px;
                padding: 10px 18px;
                min-width: 200px;
            }
            QComboBox:focus {
                border: 2px solid #00BCD4;
                background: rgba(44, 44, 64, 0.75);
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                width: 16px;
                height: 16px;
            }
        ''')
        self.bpfHelpButton = QToolButton()
        self.bpfHelpButton.setIcon(QIcon(':/icons/help.png'))
        self.bpfHelpButton.setToolTip('Show BPF filter syntax help')
        self.bpfHelpButton.setObjectName('help')
        self.bpfHelpButton.setStyleSheet('''
            QToolButton {
                background: #1976D2;
                color: white;
                border-radius: 18px;
                font-size: 16px;
                font-weight: bold;
                width: 36px;
                height: 36px;
            }
            QToolButton:hover {
                background: #00BCD4;
            }
        ''')
        self.applyButton = QPushButton('Apply')
        self.applyButton.setObjectName('applyButton')
        self.clearButton = QPushButton('Clear')
        self.clearButton.setObjectName('clearButton')
        button_style = '''
            QPushButton {
                background: #1976D2;
                color: white;
                border-radius: 14px;
                padding: 10px 24px;
                font-size: 18px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #00BCD4;
            }
            QPushButton:pressed {
                background: #0277BD;
            }
        '''
        self.applyButton.setStyleSheet(button_style)
        self.clearButton.setStyleSheet(button_style)
        filter_row.addWidget(self.filterLineEdit)
        filter_row.addWidget(self.presetCombo)
        filter_row.addWidget(self.bpfHelpButton)
        filter_row.addWidget(self.applyButton)
        filter_row.addWidget(self.clearButton)
        bpf_layout.addLayout(filter_row)
        self.bpfStatusLabel = QLabel('Status: Ready')
        self.bpfStatusLabel.setStyleSheet('''
            QLabel {
                background: rgba(44, 44, 64, 0.45);
                border-radius: 12px;
                color: #4CAF50;
                font-size: 16px;
                padding: 8px 18px;
            }
        ''')
        bpf_layout.addWidget(self.bpfStatusLabel)
        splitter.addWidget(bpf_card)

        # Display Filter Section (in a card)
        display_card = QFrame()
        display_card.setFrameShape(QFrame.StyledPanel)
        display_card.setFrameShadow(QFrame.Raised)
        display_card.setStyleSheet('''
            QFrame {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 24px;
                border: 1.5px solid rgba(255,255,255,0.10);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.10);
            }
        ''')
        display_layout = QVBoxLayout(display_card)
        display_layout.setContentsMargins(24, 24, 24, 24)
        display_layout.setSpacing(16)
        display_header = QHBoxLayout()
        display_icon = QLabel()
        display_icon.setPixmap(QPixmap(':/icons/display.png').scaled(24, 24, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        display_header.addWidget(display_icon)
        display_title = QLabel('📊 Display Filters (Post-capture Analysis)')
        display_title.setFont(QFont('Segoe UI', 18, QFont.Bold))
        display_title.setStyleSheet('color: #FF9800;')
        display_header.addWidget(display_title)
        display_header.addStretch(1)
        display_layout.addLayout(display_header)
        display_row = QHBoxLayout()
        display_row.setSpacing(16)
        self.displayFilterLineEdit = QLineEdit()
        self.displayFilterLineEdit.setPlaceholderText('ip.src == 192.168.1.1 and tcp.port == 80')
        self.displayFilterLineEdit.setStyleSheet('''
            QLineEdit {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 16px;
                border: 1.5px solid rgba(255,152,0,0.3);
                color: #E0E0E0;
                font-size: 18px;
                padding: 10px 18px;
            }
            QLineEdit:focus {
                border: 2px solid #FF9800;
                background: rgba(44, 44, 64, 0.75);
            }
        ''')
        self.displayHelpButton = QToolButton()
        self.displayHelpButton.setIcon(QIcon(':/icons/help.png'))
        self.displayHelpButton.setToolTip('Show display filter syntax help')
        self.displayHelpButton.setObjectName('help')
        self.displayHelpButton.setStyleSheet('''
            QToolButton {
                background: #FF9800;
                color: white;
                border-radius: 18px;
                font-size: 16px;
                font-weight: bold;
                width: 36px;
                height: 36px;
            }
            QToolButton:hover {
                background: #F57C00;
            }
        ''')
        self.applyDisplayButton = QPushButton('Apply')
        self.clearDisplayButton = QPushButton('Clear')
        display_button_style = '''
            QPushButton {
                background: #FF9800;
                color: white;
                border-radius: 14px;
                padding: 10px 24px;
                font-size: 18px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #F57C00;
            }
            QPushButton:pressed {
                background: #E65100;
            }
        '''
        self.applyDisplayButton.setStyleSheet(display_button_style)
        self.clearDisplayButton.setStyleSheet(display_button_style)
        display_row.addWidget(self.displayFilterLineEdit)
        display_row.addWidget(self.displayHelpButton)
        display_row.addWidget(self.applyDisplayButton)
        display_row.addWidget(self.clearDisplayButton)
        display_layout.addLayout(display_row)
        self.displayStatusLabel = QLabel('Status: Showing all packets')
        self.displayStatusLabel.setStyleSheet('''
            QLabel {
                background: rgba(44, 44, 64, 0.45);
                border-radius: 12px;
                color: #4CAF50;
                font-size: 16px;
                padding: 8px 18px;
            }
        ''')
        display_layout.addWidget(self.displayStatusLabel)
        # Filtered packets table
        self.filterTable = QTableWidget(0, 6)
        self.filterTable.setObjectName('filterTable')
        self.filterTable.setHorizontalHeaderLabels([
            'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Length', 'Info'
        ])
        self.filterTable.setAlternatingRowColors(True)
        self.filterTable.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.filterTable.setStyleSheet('''
            QTableWidget {
                background: transparent;
                border-radius: 16px;
                color: #E0E0E0;
                font-size: 18px;
                selection-background-color: #FF9800;
                selection-color: #FFFFFF;
            }
            QHeaderView::section {
                background: transparent;
                color: #B0B0B0;
                font-size: 18px;
                border: none;
                padding: 12px 0;
            }
            QTableWidget::item:hover {
                background: rgba(255, 152, 0, 0.10);
            }
        ''')
        display_layout.addWidget(self.filterTable)
        splitter.addWidget(display_card)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        main_layout.addWidget(splitter)
        self._load_filter_presets()
        
    def _create_bpf_section(self):
        """Create BPF (capture) filter section"""
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setSpacing(16)
        
        # Section title
        title = QLabel("🔍 BPF Capture Filters (Real-time)")
        title.setStyleSheet('''
            QLabel {
                color: #00BCD4;
                font-size: 20px;
                font-weight: bold;
                padding: 8px 0;
            }
        ''')
        layout.addWidget(title)
        
        # BPF filter row
        filter_row = QHBoxLayout()
        filter_row.setSpacing(16)
        
        self.filterLineEdit = QLineEdit()
        self.filterLineEdit.setPlaceholderText('tcp and (port 80 or port 443)')
        self.filterLineEdit.setObjectName('filterLineEdit')
        self.filterLineEdit.setStyleSheet('''
            QLineEdit {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 16px;
                border: 1.5px solid rgba(255,255,255,0.10);
                color: #E0E0E0;
                font-size: 18px;
                padding: 10px 18px;
            }
            QLineEdit:focus {
                border: 2px solid #00BCD4;
                background: rgba(44, 44, 64, 0.75);
            }
        ''')
        
        # Enhanced preset combo with actual BPF filters
        self.presetCombo = QComboBox()
        self.presetCombo.setObjectName('presetCombo')
        self.presetCombo.setStyleSheet('''
            QComboBox {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 16px;
                border: 1.5px solid rgba(255,255,255,0.10);
                color: #E0E0E0;
                font-size: 18px;
                padding: 10px 18px;
                min-width: 200px;
            }
            QComboBox:focus {
                border: 2px solid #00BCD4;
                background: rgba(44, 44, 64, 0.75);
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                width: 16px;
                height: 16px;
            }
        ''')
        
        # Help button for BPF syntax
        self.bpfHelpButton = QToolButton()
        self.bpfHelpButton.setText('?')
        self.bpfHelpButton.setToolTip('Show BPF filter syntax help')
        self.bpfHelpButton.setObjectName('help')
        self.bpfHelpButton.setStyleSheet('''
            QToolButton {
                background: #1976D2;
                color: white;
                border-radius: 18px;
                font-size: 16px;
                font-weight: bold;
                width: 36px;
                height: 36px;
            }
            QToolButton:hover {
                background: #00BCD4;
            }
        ''')
        
        self.applyButton = QPushButton('Apply')
        self.applyButton.setObjectName('applyButton')
        self.clearButton = QPushButton('Clear')
        self.clearButton.setObjectName('clearButton')
        
        # Style buttons
        button_style = '''
            QPushButton {
                background: #1976D2;
                color: white;
                border-radius: 14px;
                padding: 10px 24px;
                font-size: 18px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #00BCD4;
            }
            QPushButton:pressed {
                background: #0277BD;
            }
        '''
        self.applyButton.setStyleSheet(button_style)
        self.clearButton.setStyleSheet(button_style)
        
        filter_row.addWidget(self.filterLineEdit)
        filter_row.addWidget(self.presetCombo)
        filter_row.addWidget(self.bpfHelpButton)
        filter_row.addWidget(self.applyButton)
        filter_row.addWidget(self.clearButton)
        layout.addLayout(filter_row)
        
        # Status label for BPF filter
        self.bpfStatusLabel = QLabel('Status: Ready')
        self.bpfStatusLabel.setStyleSheet('''
            QLabel {
                background: rgba(44, 44, 64, 0.45);
                border-radius: 12px;
                color: #4CAF50;
                font-size: 16px;
                padding: 8px 18px;
            }
        ''')
        layout.addWidget(self.bpfStatusLabel)
        
        return section
        
    def _create_display_section(self):
        """Create display filter section"""
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setSpacing(16)
        
        # Section title
        title = QLabel("📊 Display Filters (Post-capture Analysis)")
        title.setStyleSheet('''
            QLabel {
                color: #FF9800;
                font-size: 20px;
                font-weight: bold;
                padding: 8px 0;
            }
        ''')
        layout.addWidget(title)
        
        # Display filter row
        display_row = QHBoxLayout()
        display_row.setSpacing(16)
        
        self.displayFilterLineEdit = QLineEdit()
        self.displayFilterLineEdit.setPlaceholderText('ip.src == 192.168.1.1 and tcp.port == 80')
        self.displayFilterLineEdit.setStyleSheet('''
            QLineEdit {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 16px;
                border: 1.5px solid rgba(255,152,0,0.3);
                color: #E0E0E0;
                font-size: 18px;
                padding: 10px 18px;
            }
            QLineEdit:focus {
                border: 2px solid #FF9800;
                background: rgba(44, 44, 64, 0.75);
            }
        ''')
        
        # Display filter help button
        self.displayHelpButton = QToolButton()
        self.displayHelpButton.setText('?')
        self.displayHelpButton.setToolTip('Show display filter syntax help')
        self.displayHelpButton.setObjectName('help')
        self.displayHelpButton.setStyleSheet('''
            QToolButton {
                background: #FF9800;
                color: white;
                border-radius: 18px;
                font-size: 16px;
                font-weight: bold;
                width: 36px;
                height: 36px;
            }
            QToolButton:hover {
                background: #F57C00;
            }
        ''')
        
        self.applyDisplayButton = QPushButton('Apply')
        self.clearDisplayButton = QPushButton('Clear')
        
        display_button_style = '''
            QPushButton {
                background: #FF9800;
                color: white;
                border-radius: 14px;
                padding: 10px 24px;
                font-size: 18px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #F57C00;
            }
            QPushButton:pressed {
                background: #E65100;
            }
        '''
        self.applyDisplayButton.setStyleSheet(display_button_style)
        self.clearDisplayButton.setStyleSheet(display_button_style)
        
        display_row.addWidget(self.displayFilterLineEdit)
        display_row.addWidget(self.displayHelpButton)
        display_row.addWidget(self.applyDisplayButton)
        display_row.addWidget(self.clearDisplayButton)
        layout.addLayout(display_row)
        
        # Status label for display filter
        self.displayStatusLabel = QLabel('Status: Showing all packets')
        self.displayStatusLabel.setStyleSheet('''
            QLabel {
                background: rgba(44, 44, 64, 0.45);
                border-radius: 12px;
                color: #4CAF50;
                font-size: 16px;
                padding: 8px 18px;
            }
        ''')
        layout.addWidget(self.displayStatusLabel)
        
        # Filtered packets table
        self.filterTable = QTableWidget(0, 6)
        self.filterTable.setObjectName('filterTable')
        self.filterTable.setHorizontalHeaderLabels([
            'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Length', 'Info'
        ])
        self.filterTable.setAlternatingRowColors(True)
        self.filterTable.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.filterTable.setStyleSheet('''
            QTableWidget {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 24px;
                border: 1.5px solid rgba(255,152,0,0.2);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.18);
                color: #E0E0E0;
                font-size: 18px;
                selection-background-color: #FF9800;
                selection-color: #FFFFFF;
            }
            QHeaderView::section {
                background: transparent;
                color: #B0B0B0;
                font-size: 18px;
                border: none;
                padding: 12px 0;
            }
            QTableWidget::item:hover {
                background: rgba(255, 152, 0, 0.10);
            }
        ''')
        layout.addWidget(self.filterTable)
        
        return section
        
    def _load_filter_presets(self):
        """Load BPF filter presets"""
        try:
            if get_common_filters:
                common_filters = get_common_filters()
                self.presetCombo.addItem("None", "")
                for name, filter_expr in common_filters.items():
                    display_name = name.replace('_', ' ').title()
                    self.presetCombo.addItem(display_name, filter_expr)
            else:
                # Fallback presets
                presets = {
                    "Web Traffic": "tcp and (port 80 or port 443)",
                    "DNS Traffic": "udp and port 53",
                    "Email Traffic": "tcp and (port 25 or port 110 or port 143)",
                    "SSH Traffic": "tcp and port 22",
                    "ICMP Traffic": "icmp",
                    "ARP Traffic": "arp",
                    "Large Packets": "len > 1000"
                }
                self.presetCombo.addItem("None", "")
                for name, filter_expr in presets.items():
                    self.presetCombo.addItem(name, filter_expr)
        except Exception as e:
            print(f"Error loading filter presets: {e}")
            
        # Connect signals
        self._connect_signals()
        
    def _connect_signals(self):
        """Connect UI signals"""
        # BPF filter signals
        self.presetCombo.currentTextChanged.connect(self._on_preset_changed)
        self.filterLineEdit.textChanged.connect(self._validate_bpf_filter)
        self.bpfHelpButton.clicked.connect(self._show_bpf_help)
        self.applyButton.clicked.connect(self._apply_bpf_filter)
        self.clearButton.clicked.connect(self._clear_bpf_filter)
        
        # Display filter signals  
        self.displayFilterLineEdit.textChanged.connect(self._validate_display_filter)
        self.displayHelpButton.clicked.connect(self._show_display_help)
        self.applyDisplayButton.clicked.connect(self._apply_display_filter)
        self.clearDisplayButton.clicked.connect(self._clear_display_filter)
        
    def _on_preset_changed(self):
        """Handle preset selection"""
        current_data = self.presetCombo.currentData()
        if current_data:
            self.filterLineEdit.setText(current_data)
            
    def _validate_bpf_filter(self):
        """Validate BPF filter syntax"""
        filter_text = self.filterLineEdit.text()
        if not filter_text.strip():
            self._update_bpf_status("Ready", "#4CAF50")
            return
            
        if validate_filter:
            is_valid, message = validate_filter(filter_text)
            if is_valid:
                self._update_bpf_status("✓ Valid BPF syntax", "#4CAF50")
            else:
                self._update_bpf_status(f"✗ {message}", "#F44336")
        else:
            self._update_bpf_status("Validation unavailable", "#FF9800")
            
    def _validate_display_filter(self):
        """Validate display filter syntax"""  
        filter_text = self.displayFilterLineEdit.text()
        if not filter_text.strip():
            self._update_display_status("Showing all packets", "#4CAF50")
            return
            
        # Basic syntax check for display filters
        try:
            # Simple validation - check for valid field names and operators
            valid_fields = ['ip.src', 'ip.dst', 'tcp.port', 'udp.port', 'protocol', 'frame.len']
            valid_operators = ['==', '!=', '>', '<', '>=', '<=', 'contains', 'matches']
            
            has_field = any(field in filter_text for field in valid_fields)
            has_operator = any(op in filter_text for op in valid_operators)
            
            if has_field and has_operator:
                self._update_display_status("✓ Valid display filter syntax", "#4CAF50")
            else:
                self._update_display_status("⚠ Check syntax - use fields like ip.src, tcp.port", "#FF9800")
        except Exception as e:
            self._update_display_status(f"✗ Syntax error: {str(e)}", "#F44336")
            
    def _update_bpf_status(self, message, color):
        """Update BPF status label"""
        self.bpfStatusLabel.setText(f"Status: {message}")
        self.bpfStatusLabel.setStyleSheet(f'''
            QLabel {{
                background: rgba(44, 44, 64, 0.45);
                border-radius: 12px;
                color: {color};
                font-size: 16px;
                padding: 8px 18px;
            }}
        ''')
        
    def _update_display_status(self, message, color):
        """Update display status label"""
        self.displayStatusLabel.setText(f"Status: {message}")
        self.displayStatusLabel.setStyleSheet(f'''
            QLabel {{
                background: rgba(44, 44, 64, 0.45);
                border-radius: 12px;
                color: {color};
                font-size: 16px;
                padding: 8px 18px;
            }}
        ''')
        
    def _show_bpf_help(self):
        """Show BPF filter help"""
        if get_filter_help:
            help_text = get_filter_help()
        else:
            help_text = """
BPF (Berkeley Packet Filter) Syntax:

Protocol Filters:
• tcp - TCP packets only
• udp - UDP packets only  
• icmp - ICMP packets only
• arp - ARP packets only

Host and Network:
• host 192.168.1.1 - Traffic to/from host
• net 192.168.1.0/24 - Traffic to/from network

Port Filters:
• port 80 - Traffic on port 80
• src port 80 - Traffic from port 80
• dst port 80 - Traffic to port 80

Examples:
• tcp and port 80
• udp and port 53
• host 8.8.8.8 and tcp
• not arp and not icmp
            """
        
        msg = QMessageBox(self)
        msg.setWindowTitle("BPF Filter Help")
        msg.setText(help_text)
        msg.setStyleSheet('''
            QMessageBox {
                background: #2C2C40;
                color: #E0E0E0;
            }
            QMessageBox QLabel {
                color: #E0E0E0;
                font-size: 14px;
            }
        ''')
        msg.exec_()
        
    def _show_display_help(self):
        """Show display filter help"""
        if get_display_filter_help:
            help_text = get_display_filter_help()
        else:
            help_text = """
Display Filter Syntax (Wireshark-style):

Field Names:
• ip.src - Source IP address
• ip.dst - Destination IP address  
• tcp.port - TCP port (any direction)
• udp.port - UDP port (any direction)
• protocol - Protocol name
• frame.len - Packet length

Operators:
• == - Equal
• != - Not equal
• > < >= <= - Comparisons
• contains - Contains substring
• matches - Regular expression

Examples:
• ip.src == 192.168.1.1
• tcp.port == 80
• protocol == TCP and frame.len > 1000
• dns.qry.name contains google
            """
        
        msg = QMessageBox(self)
        msg.setWindowTitle("Display Filter Help")
        msg.setText(help_text)
        msg.setStyleSheet('''
            QMessageBox {
                background: #2C2C40;
                color: #E0E0E0;
            }
            QMessageBox QLabel {
                color: #E0E0E0;
                font-size: 14px;
            }
        ''')
        msg.exec_()
        
    def _apply_bpf_filter(self):
        """Apply BPF filter"""
        bpf_filter = self.filterLineEdit.text()
        self.filterApplied.emit(bpf_filter, "")
        
    def _clear_bpf_filter(self):
        """Clear BPF filter"""
        self.filterLineEdit.clear()
        self.presetCombo.setCurrentIndex(0)
        
    def _apply_display_filter(self):
        """Apply display filter"""
        display_filter = self.displayFilterLineEdit.text()
        self.filterApplied.emit("", display_filter)
        self._refresh_filtered_table()
        
    def _clear_display_filter(self):
        """Clear display filter"""
        self.displayFilterLineEdit.clear()
        self._refresh_filtered_table()
        
    def _refresh_filtered_table(self):
        """Refresh the filtered packets table"""
        display_filter = self.displayFilterLineEdit.text().strip()
        
        try:
            # Use the advanced packet viewer to filter packets
            if AdvancedPacketViewer:
                with AdvancedPacketViewer('packets.db') as viewer:
                    packets = viewer.get_packets(limit=1000)  # Limit for performance
                    
                    if display_filter:
                        filtered_packets = viewer.filter_packets(packets, display_filter)
                    else:
                        filtered_packets = packets
                    
                    # Update table
                    self._populate_filter_table(filtered_packets)
                    self._update_display_status(f"Showing {len(filtered_packets)} packets", "#4CAF50")
            else:
                self._update_display_status("Advanced filtering not available", "#FF9800")
                
        except Exception as e:
            self._update_display_status(f"Error: {str(e)}", "#F44336")
            
    def _populate_filter_table(self, packets):
        """Populate the filter table with packets"""
        self.filterTable.setRowCount(len(packets))
        
        for row, packet in enumerate(packets):
            # Format packet info similar to Wireshark
            timestamp = packet.get('timestamp', '')
            src_ip = packet.get('src_ip', '')
            dst_ip = packet.get('dst_ip', '')
            protocol = packet.get('protocol', '')
            size = str(packet.get('size', ''))
            
            # Generate info string
            info = self._generate_packet_info(packet)
            
            # Set table items
            items = [timestamp, src_ip, dst_ip, protocol, size, info]
            for col, item_text in enumerate(items):
                item = QTableWidgetItem(str(item_text))
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                self.filterTable.setItem(row, col, item)
                
        # Adjust column widths
        self.filterTable.resizeColumnsToContents()
        
    def _generate_packet_info(self, packet):
        """Generate info string for packet (similar to Wireshark)"""
        protocol = packet.get('protocol', '').upper()
        
        if protocol == 'TCP':
            src_port = packet.get('src_port', '')
            dst_port = packet.get('dst_port', '')
            flags = packet.get('tcp_flags', '')
            return f"{src_port} → {dst_port} [{flags}]"
            
        elif protocol == 'UDP':
            src_port = packet.get('src_port', '')
            dst_port = packet.get('dst_port', '')
            return f"{src_port} → {dst_port}"
            
        elif protocol == 'ICMP':
            icmp_type = packet.get('icmp_type', '')
            icmp_code = packet.get('icmp_code', '')
            return f"Type={icmp_type} Code={icmp_code}"
            
        elif protocol == 'DNS':
            query = packet.get('dns_qd', '')
            if query:
                return f"Query {query}"
            else:
                return "DNS"
                
        elif protocol == 'ARP':
            op = packet.get('arp_op', '')
            op_name = {1: 'Request', 2: 'Reply'}.get(op, f'Op={op}')
            return f"{op_name}"
            
        return ""
        
    def get_current_bpf_filter(self):
        """Get current BPF filter"""
        return self.filterLineEdit.text()
        
    def get_current_display_filter(self):
        """Get current display filter"""
        return self.displayFilterLineEdit.text()
        
    def set_bpf_filter(self, filter_text):
        """Set BPF filter"""
        self.filterLineEdit.setText(filter_text)
        
    def set_display_filter(self, filter_text):
        """Set display filter"""
        self.displayFilterLineEdit.setText(filter_text) 