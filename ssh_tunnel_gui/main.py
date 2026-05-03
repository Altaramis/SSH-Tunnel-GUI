# Copyright (C) 2026  Altaramis
# SPDX-License-Identifier: GPL-3.0-or-later
import argparse
import os
import sys
from PyQt6.QtGui import QIcon
from PyQt6.QtNetwork import QLocalServer, QLocalSocket
from PyQt6.QtWidgets import QApplication, QMessageBox
from ssh_tunnel_gui.app import MainWindow
from ssh_tunnel_gui._version import __version__

_LOGO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logo.ico')
_IPC_NAME = 'ssh_tunnel_gui_instance'


def main() -> None:
    parser = argparse.ArgumentParser(prog='ssh_tunnel_gui', add_help=False)
    parser.add_argument('--version', action='version', version=f'SSH Tunnel GUI {__version__}')
    parser.parse_known_args()

    app = QApplication(sys.argv)
    app.setApplicationName('SSH Tunnel GUI')
    icon = QIcon(_LOGO)
    app.setWindowIcon(icon)

    socket = QLocalSocket()
    socket.connectToServer(_IPC_NAME)
    already_running = socket.waitForConnected(500)
    socket.disconnectFromServer()
    socket.deleteLater()

    if already_running:
        msg = QMessageBox()
        msg.setWindowTitle('SSH Tunnel GUI')
        msg.setWindowIcon(icon)
        msg.setText('Une instance de SSH Tunnel GUI est déjà en cours d\'exécution.')
        msg.setInformativeText('Voulez-vous quand même lancer une nouvelle instance ?')
        msg.setIcon(QMessageBox.Icon.Warning)
        btn_launch = msg.addButton('Lancer quand même', QMessageBox.ButtonRole.AcceptRole)
        msg.addButton('Annuler', QMessageBox.ButtonRole.RejectRole)
        msg.exec()
        if msg.clickedButton() is not btn_launch:
            sys.exit(0)
    else:
        # First instance — create the server so subsequent launches can detect it
        server = QLocalServer()
        QLocalServer.removeServer(_IPC_NAME)
        server.listen(_IPC_NAME)  # IPC local uniquement (pipe nommé Windows / socket Unix) — aucun port réseau ouvert
        app.server = server  # keep alive for the duration of the app

    window = MainWindow()
    window.show()
    sys.exit(app.exec())
