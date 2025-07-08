from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, QSlider, QLabel, QTableWidget
from PyQt5.QtCore import Qt

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