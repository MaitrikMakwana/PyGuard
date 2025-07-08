from PyQt5.QtWidgets import QWidget, QSplitter, QTreeWidget, QTextEdit, QHBoxLayout, QSizePolicy
from PyQt5.QtCore import Qt

class PacketDetailsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        splitter = QSplitter(Qt.Horizontal)
        self.protocolTree = QTreeWidget()
        self.protocolTree.setObjectName('protocolTree')
        self.protocolTree.setHeaderLabel('Protocol Layers & Fields')
        self.protocolTree.setStyleSheet('''
            QTreeWidget {
                background: rgba(44, 44, 64, 0.65);
                border-radius: 24px;
                border: 1.5px solid rgba(255,255,255,0.10);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.18);
                color: #E0E0E0;
                font-size: 20px;
                font-weight: bold;
                padding: 24px;
            }
            QTreeWidget::item {
                font-size: 18px;
                font-weight: normal;
                padding: 8px 0;
            }
        ''')
        self.hexDumpEdit = QTextEdit()
        self.hexDumpEdit.setObjectName('hexDumpEdit')
        self.hexDumpEdit.setReadOnly(True)
        self.hexDumpEdit.setStyleSheet('''
            QTextEdit {
                background: rgba(44, 44, 64, 0.65);
                border-radius: 24px;
                border: 1.5px solid rgba(255,255,255,0.10);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.18);
                color: #E0E0E0;
                font-size: 18px;
                font-family: 'Fira Mono', 'Consolas', 'monospace';
                padding: 24px;
            }
        ''')
        self.protocolTree.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.hexDumpEdit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        splitter.addWidget(self.protocolTree)
        splitter.addWidget(self.hexDumpEdit)
        splitter.setSizes([400, 800])
        layout = QHBoxLayout(self)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(32)
        layout.addWidget(splitter) 