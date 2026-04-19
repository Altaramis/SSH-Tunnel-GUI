# Copyright (C) 2026  Altaramis
# SPDX-License-Identifier: GPL-3.0-or-later
import os
import sys
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication
from ssh_tunnel_gui.app import MainWindow

_LOGO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logo.ico')


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName('SSH Tunnel GUI')
    icon = QIcon(_LOGO)
    app.setWindowIcon(icon)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
