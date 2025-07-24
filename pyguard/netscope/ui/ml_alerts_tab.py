from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, QSlider, QLabel, QTableWidget, QFrame, QPushButton, QSizePolicy
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QIcon, QPixmap
from PyQt5.QtWidgets import QHeaderView

class MLAlertsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(32, 32, 32, 32)
        main_layout.setSpacing(24)

        # Action Bar (fixed at top)
        action_bar = QHBoxLayout()
        action_bar.setSpacing(16)
        ml_icon = QLabel()
        ml_icon.setPixmap(QPixmap(':/icons/ml.png').scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        ml_icon.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        action_bar.addWidget(ml_icon)
        section_title = QLabel('ML Alerts')
        section_title.setFont(QFont('Segoe UI', 22, QFont.Bold))
        section_title.setStyleSheet('color: #00BCD4;')
        action_bar.addWidget(section_title)
        action_bar.addStretch(1)
        main_layout.addLayout(action_bar)

        # ML Controls Card
        controls_card = QFrame()
        controls_card.setFrameShape(QFrame.StyledPanel)
        controls_card.setFrameShadow(QFrame.Raised)
        controls_card.setStyleSheet('''
            QFrame {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 18px;
                border: 1.5px solid rgba(255,255,255,0.10);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.10);
            }
        ''')
        controls_layout = QHBoxLayout(controls_card)
        controls_layout.setContentsMargins(24, 18, 24, 18)
        controls_layout.setSpacing(16)
        self.mlToggle = QCheckBox('Enable ML Detection')
        self.mlToggle.setObjectName('mlToggle')
        self.mlToggle.setFont(QFont('Segoe UI', 16))
        self.thresholdSlider = QSlider(Qt.Horizontal)
        self.thresholdSlider.setObjectName('thresholdSlider')
        self.thresholdSlider.setMinimum(0)
        self.thresholdSlider.setMaximum(100)
        self.thresholdSlider.setValue(70)
        self.thresholdSlider.setSingleStep(1)
        self.thresholdLabel = QLabel('Threshold: 0.70')
        self.thresholdLabel.setObjectName('thresholdLabel')
        self.thresholdLabel.setFont(QFont('Segoe UI', 16))
        controls_layout.addWidget(self.mlToggle)
        controls_layout.addWidget(self.thresholdSlider)
        controls_layout.addWidget(self.thresholdLabel)
        controls_layout.addStretch()
        main_layout.addWidget(controls_card)

        # Alerts Table Card
        table_card = QFrame()
        table_card.setFrameShape(QFrame.StyledPanel)
        table_card.setFrameShadow(QFrame.Raised)
        table_card.setStyleSheet('''
            QFrame {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 24px;
                border: 1.5px solid rgba(255,255,255,0.10);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.10);
            }
        ''')
        table_layout = QVBoxLayout(table_card)
        table_layout.setContentsMargins(24, 24, 24, 24)
        table_layout.setSpacing(16)
        table_header = QLabel('ML Alerts Table')
        table_header.setFont(QFont('Segoe UI', 18, QFont.Bold))
        table_header.setStyleSheet('color: #FF9800;')
        table_layout.addWidget(table_header)
        self.alertsTable = QTableWidget(0, 4)
        self.alertsTable.setObjectName('alertsTable')
        self.alertsTable.setHorizontalHeaderLabels([
            'Time', 'Source IP', 'Threat Type', 'Confidence'
        ])
        self.alertsTable.setAlternatingRowColors(True)
        self.alertsTable.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.alertsTable.setStyleSheet('''
            QTableWidget {
                background: transparent;
                border-radius: 16px;
                color: #E0E0E0;
                font-size: 18px;
                selection-background-color: #00BCD4;
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
                background: rgba(0, 188, 212, 0.10);
            }
        ''')
        table_layout.addWidget(self.alertsTable)
        main_layout.addWidget(table_card) 