from PyQt5.QtWidgets import QWidget, QFormLayout, QComboBox, QPushButton, QLabel, QHBoxLayout, QCheckBox, QVBoxLayout, QFrame
from PyQt5.QtGui import QFont, QPixmap
from PyQt5.QtCore import Qt

class SettingsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(32, 32, 32, 32)
        main_layout.setSpacing(24)

        # Action Bar (fixed at top)
        action_bar = QHBoxLayout()
        action_bar.setSpacing(16)
        settings_icon = QLabel()
        settings_icon.setPixmap(QPixmap(':/icons/settings.png').scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        settings_icon.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        action_bar.addWidget(settings_icon)
        section_title = QLabel('Settings')
        section_title.setFont(QFont('Segoe UI', 22, QFont.Bold))
        section_title.setStyleSheet('color: #00BCD4;')
        action_bar.addWidget(section_title)
        action_bar.addStretch(1)
        main_layout.addLayout(action_bar)

        # Settings Form Card
        form_card = QFrame()
        form_card.setFrameShape(QFrame.StyledPanel)
        form_card.setFrameShadow(QFrame.Raised)
        form_card.setStyleSheet('''
            QFrame {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 24px;
                border: 1.5px solid rgba(255,255,255,0.10);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.10);
            }
        ''')
        form_layout = QFormLayout(form_card)
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
        form_layout.addRow('Default Interface:', self.defaultInterfaceCombo)
        form_layout.addRow('Autosave Location:', autosave_widget)
        form_layout.addRow('', self.soundAlertsCheck)
        form_layout.addRow('ML Model Path:', mlmodel_widget)
        form_layout.addRow('Theme:', self.themeToggle)
        main_layout.addWidget(form_card) 