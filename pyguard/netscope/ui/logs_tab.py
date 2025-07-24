from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, QPushButton, QPlainTextEdit, QFrame, QLabel
from PyQt5.QtGui import QFont, QIcon, QPixmap
from PyQt5.QtCore import Qt

class LogsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(32, 32, 32, 32)
        main_layout.setSpacing(24)

        # Action Bar (fixed at top)
        action_bar = QHBoxLayout()
        action_bar.setSpacing(16)
        logs_icon = QLabel()
        logs_icon.setPixmap(QPixmap(':/icons/logs.png').scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logs_icon.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        action_bar.addWidget(logs_icon)
        section_title = QLabel('Logs')
        section_title.setFont(QFont('Segoe UI', 22, QFont.Bold))
        section_title.setStyleSheet('color: #00BCD4;')
        action_bar.addWidget(section_title)
        action_bar.addStretch(1)
        main_layout.addLayout(action_bar)

        # Log Filter Controls Card
        filter_card = QFrame()
        filter_card.setFrameShape(QFrame.StyledPanel)
        filter_card.setFrameShadow(QFrame.Raised)
        filter_card.setStyleSheet('''
            QFrame {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 18px;
                border: 1.5px solid rgba(255,255,255,0.10);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.10);
            }
        ''')
        filter_layout = QHBoxLayout(filter_card)
        filter_layout.setContentsMargins(24, 18, 24, 18)
        filter_layout.setSpacing(16)
        self.systemLogCheck = QCheckBox('System Logs')
        self.systemLogCheck.setObjectName('systemLogCheck')
        self.packetLogCheck = QCheckBox('Packet Logs')
        self.packetLogCheck.setObjectName('packetLogCheck')
        self.mlLogCheck = QCheckBox('ML Logs')
        self.mlLogCheck.setObjectName('mlLogCheck')
        self.exportLogsButton = QPushButton('Export Logs')
        self.exportLogsButton.setObjectName('exportLogsButton')
        filter_layout.addWidget(self.systemLogCheck)
        filter_layout.addWidget(self.packetLogCheck)
        filter_layout.addWidget(self.mlLogCheck)
        filter_layout.addStretch()
        filter_layout.addWidget(self.exportLogsButton)
        main_layout.addWidget(filter_card)

        # Log Output Card
        output_card = QFrame()
        output_card.setFrameShape(QFrame.StyledPanel)
        output_card.setFrameShadow(QFrame.Raised)
        output_card.setStyleSheet('''
            QFrame {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 24px;
                border: 1.5px solid rgba(255,255,255,0.10);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.10);
            }
        ''')
        output_layout = QVBoxLayout(output_card)
        output_layout.setContentsMargins(24, 24, 24, 24)
        output_layout.setSpacing(16)
        output_header = QLabel('Log Output')
        output_header.setFont(QFont('Segoe UI', 18, QFont.Bold))
        output_header.setStyleSheet('color: #FF9800;')
        output_layout.addWidget(output_header)
        self.logOutput = QPlainTextEdit()
        self.logOutput.setObjectName('logOutput')
        self.logOutput.setReadOnly(True)
        self.logOutput.setStyleSheet('''
            QPlainTextEdit {
                background: transparent;
                border-radius: 12px;
                color: #E0E0E0;
                font-size: 18px;
                font-family: 'Fira Mono', 'Consolas', 'monospace';
                padding: 12px;
            }
        ''')
        output_layout.addWidget(self.logOutput)
        main_layout.addWidget(output_card) 