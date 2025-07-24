from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QFrame, QHBoxLayout
from PyQt5.QtGui import QFont, QPixmap
from PyQt5.QtCore import Qt

class AboutTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(32, 32, 32, 32)
        main_layout.setSpacing(24)

        # Action Bar (fixed at top)
        action_bar = QHBoxLayout()
        action_bar.setSpacing(16)
        about_icon = QLabel()
        about_icon.setPixmap(QPixmap(':/icons/about.png').scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        about_icon.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        action_bar.addWidget(about_icon)
        section_title = QLabel('About')
        section_title.setFont(QFont('Segoe UI', 22, QFont.Bold))
        section_title.setStyleSheet('color: #00BCD4;')
        action_bar.addWidget(section_title)
        action_bar.addStretch(1)
        main_layout.addLayout(action_bar)

        # About Content Card
        about_card = QFrame()
        about_card.setFrameShape(QFrame.StyledPanel)
        about_card.setFrameShadow(QFrame.Raised)
        about_card.setStyleSheet('''
            QFrame {
                background: rgba(44, 44, 64, 0.55);
                border-radius: 24px;
                border: 1.5px solid rgba(255,255,255,0.10);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.10);
            }
        ''')
        about_layout = QVBoxLayout(about_card)
        about_layout.setContentsMargins(24, 24, 24, 24)
        about_layout.setSpacing(16)
        title = QLabel('PyGuard v1.0')
        title.setFont(QFont('Segoe UI', 20, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(title)
        desc = QLabel('Built with PyQt5, Scapy, scikit-learn')
        desc.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(desc)
        mit = QLabel('''MIT License\n\nCopyright (c) 2024\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the \"Software\"), to deal\nin the Software without restriction, including without limitation the rights\nto use, copy, modify, merge, publish, distribute, sublicense, and/or sell\ncopies of the Software, and to permit persons to whom the Software is\nfurnished to do so, subject to the following conditions: ...''')
        mit.setAlignment(Qt.AlignLeft)
        mit.setWordWrap(True)
        about_layout.addWidget(mit)
        links = QLabel('<a href="https://github.com/yourrepo">GitHub</a> | <a href="https://docs.example.com">Docs</a> | <a href="mailto:dev@example.com">Contact</a>')
        links.setOpenExternalLinks(True)
        links.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(links)
        about_layout.addStretch()
        main_layout.addWidget(about_card) 