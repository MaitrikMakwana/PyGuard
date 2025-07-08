from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QSizePolicy

class LiveCaptureTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(16)
        self.packetTable = QTableWidget(0, 6)
        self.packetTable.setObjectName('packetTable')
        self.packetTable.setHorizontalHeaderLabels([
            'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Length', 'Info'
        ])
        self.packetTable.setAlternatingRowColors(True)
        self.packetTable.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.packetTable.setStyleSheet('''
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
        layout.addWidget(self.packetTable)
        layout.setStretch(0, 1)  # Make table expand 