from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt

class AboutTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        title = QLabel('PyGuard v1.0')
        title.setFont(QFont('Segoe UI', 20, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        desc = QLabel('Built with PyQt5, Scapy, scikit-learn')
        desc.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc)
        mit = QLabel('''MIT License\n\nCopyright (c) 2024\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the \"Software\"), to deal\nin the Software without restriction, including without limitation the rights\nto use, copy, modify, merge, publish, distribute, sublicense, and/or sell\ncopies of the Software, and to permit persons to whom the Software is\nfurnished to do so, subject to the following conditions: ...''')
        mit.setAlignment(Qt.AlignLeft)
        mit.setWordWrap(True)
        layout.addWidget(mit)
        links = QLabel('<a href="https://github.com/yourrepo">GitHub</a> | <a href="https://docs.example.com">Docs</a> | <a href="mailto:dev@example.com">Contact</a>')
        links.setOpenExternalLinks(True)
        links.setAlignment(Qt.AlignCenter)
        layout.addWidget(links)
        layout.addStretch() 