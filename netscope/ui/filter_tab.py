from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QComboBox, QPushButton, QLabel, QTableWidget, QSizePolicy

class FilterTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(24)
        filter_row = QHBoxLayout()
        filter_row.setSpacing(16)
        self.filterLineEdit = QLineEdit()
        self.filterLineEdit.setPlaceholderText('tcp port 443')
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
        self.presetCombo.addItems(['All', 'HTTP', 'HTTPS', 'DNS', 'ICMP', 'ARP'])
        self.presetCombo.setStyleSheet('''
            QComboBox {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 16px;
                border: 1.5px solid rgba(255,255,255,0.10);
                color: #E0E0E0;
                font-size: 18px;
                padding: 10px 18px;
            }
            QComboBox:focus {
                border: 2px solid #00BCD4;
                background: rgba(44, 44, 64, 0.75);
            }
        ''')
        self.applyButton = QPushButton('Apply')
        self.applyButton.setObjectName('applyButton')
        self.clearButton = QPushButton('Clear')
        self.clearButton.setObjectName('clearButton')
        self.applyButton.setStyleSheet('border-radius: 14px; padding: 10px 24px; font-size: 18px;')
        self.clearButton.setStyleSheet('border-radius: 14px; padding: 10px 24px; font-size: 18px;')
        filter_row.addWidget(self.filterLineEdit)
        filter_row.addWidget(self.presetCombo)
        filter_row.addWidget(self.applyButton)
        filter_row.addWidget(self.clearButton)
        layout.addLayout(filter_row)
        self.activeFilterLabel = QLabel('Current Filter: All')
        self.activeFilterLabel.setObjectName('activeFilterLabel')
        self.activeFilterLabel.setStyleSheet('''
            QLabel {
                background: rgba(44, 44, 64, 0.45);
                border-radius: 12px;
                color: #00BCD4;
                font-size: 16px;
                padding: 8px 18px;
                margin-bottom: 8px;
            }
        ''')
        layout.addWidget(self.activeFilterLabel)
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
                border: 1.5px solid rgba(255,255,255,0.08);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.18);
                color: #E0E0E0;
                font-size: 18px;
                selection-background-color: #1976D2;
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
                background: rgba(25, 118, 210, 0.10);
            }
        ''')
        layout.addWidget(self.filterTable)
        layout.setStretch(2, 1) 