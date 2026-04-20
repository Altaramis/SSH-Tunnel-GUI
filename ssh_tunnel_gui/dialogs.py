# Copyright (C) 2026  Altaramis
# SPDX-License-Identifier: GPL-3.0-or-later
"""All modal dialogs for the SSH tunnel GUI (PyQt6)."""

from typing import Any, Dict, List, Optional

import paramiko
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
    QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMessageBox, QPlainTextEdit, QPushButton, QRadioButton, QSpinBox,
    QSplitter, QVBoxLayout, QWidget,
)

from ssh_tunnel_gui.encryption import KEYRING_AVAILABLE
from ssh_tunnel_lib.connection import _load_private_key


class MasterPasswordDialog(QDialog):
    def __init__(self, parent: Optional[QWidget] = None,
                 initial_pwd: Optional[str] = None,
                 initial_remember: bool = False) -> None:
        super().__init__(parent)
        self.setWindowTitle('Master Password')
        self.setModal(True)
        self.setMinimumWidth(360)

        layout = QFormLayout(self)
        layout.setContentsMargins(16, 16, 16, 8)

        self._pwd = QLineEdit()
        self._pwd.setEchoMode(QLineEdit.EchoMode.Password)
        if initial_pwd:
            self._pwd.setText(initial_pwd)
        layout.addRow('Master Password:', self._pwd)

        remember_label = ('Remember password (OS keyring)' if KEYRING_AVAILABLE
                          else 'Remember password (install keyring to enable)')
        self._remember = QCheckBox(remember_label)
        self._remember.setChecked(initial_remember and KEYRING_AVAILABLE)
        self._remember.setEnabled(KEYRING_AVAILABLE)
        layout.addRow(self._remember)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self._accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

        self._pwd.returnPressed.connect(self._accept)
        self._pwd.setFocus()

    def _accept(self) -> None:
        if not self._pwd.text():
            QMessageBox.warning(self, 'Error', 'Master password cannot be empty.')
            return
        self.accept()

    @property
    def password(self) -> str:
        return self._pwd.text()

    @property
    def remember(self) -> bool:
        return self._remember.isChecked()


class ChangeMasterPasswordDialog(QDialog):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle('Change Master Password')
        self.setModal(True)
        self.setMinimumWidth(360)

        layout = QFormLayout(self)
        layout.setContentsMargins(16, 16, 16, 8)

        self._old = QLineEdit(); self._old.setEchoMode(QLineEdit.EchoMode.Password)
        self._new1 = QLineEdit(); self._new1.setEchoMode(QLineEdit.EchoMode.Password)
        self._new2 = QLineEdit(); self._new2.setEchoMode(QLineEdit.EchoMode.Password)

        layout.addRow('Current password:', self._old)
        layout.addRow('New password:', self._new1)
        layout.addRow('Confirm new:', self._new2)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self._accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def _accept(self) -> None:
        if not self._new1.text():
            QMessageBox.warning(self, 'Error', 'New password cannot be empty.')
            return
        if self._new1.text() != self._new2.text():
            QMessageBox.warning(self, 'Error', 'New passwords do not match.')
            return
        self.accept()

    @property
    def old_password(self) -> str:
        return self._old.text()

    @property
    def new_password(self) -> str:
        return self._new1.text()


class TunnelConfigDialog(QDialog):
    """Create or edit a tunnel profile."""

    _PROXY_TYPES = ['socks5', 'socks4', 'http']

    def __init__(self, parent: Optional[QWidget] = None,
                 initial: Optional[Dict[str, Any]] = None,
                 name: Optional[str] = None,
                 has_parent: bool = False,
                 locked: bool = False) -> None:
        super().__init__(parent)
        self.setWindowTitle('Edit tunnel' if initial else 'Add tunnel')
        self.setModal(True)
        self.setMinimumWidth(420)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 8)

        if locked:
            notice = QLabel('⚠ Tunnel is running — only name and lifecycle settings can be changed.')
            notice.setWordWrap(True)
            notice.setStyleSheet('color: #b8860b; padding: 4px 0;')
            main_layout.addWidget(notice)

        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        main_layout.addLayout(form)

        # ---- Basic ----
        self._name = QLineEdit()
        self._auto_start = QCheckBox('Enabled')
        self._auto_start.setChecked(True)
        form.addRow('Profile name:', self._name)
        form.addRow('Auto-start:', self._auto_start)

        # ---- SSH server ----
        ssh_box = QGroupBox('SSH Server')
        ssh_form = QFormLayout(ssh_box)
        self._host = QLineEdit()
        self._port = QSpinBox(); self._port.setRange(1, 65535); self._port.setValue(22)
        self._user = QLineEdit()
        ssh_form.addRow('Host:', self._host)
        ssh_form.addRow('Port:', self._port)
        ssh_form.addRow('Username:', self._user)
        main_layout.addWidget(ssh_box)

        # ---- Authentication ----
        auth_box = QGroupBox('Authentication')
        auth_form = QFormLayout(auth_box)
        self._use_agent = QCheckBox('Use SSH Agent')
        self._use_agent.setChecked(True)
        self._password = QLineEdit(); self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._keyfile = QLineEdit()
        browse_btn = QPushButton('Browse…')
        browse_btn.setFixedWidth(80)
        browse_btn.clicked.connect(self._browse_key)
        key_row = QWidget(); key_hl = QHBoxLayout(key_row); key_hl.setContentsMargins(0,0,0,0)
        key_hl.addWidget(self._keyfile); key_hl.addWidget(browse_btn)
        self._passphrase = QLineEdit(); self._passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self._verify_btn = QPushButton('Verify'); self._verify_btn.setFixedWidth(60)
        self._verify_btn.setEnabled(False)
        self._verify_lbl = QLabel()
        self._verify_btn.clicked.connect(self._verify_passphrase)
        self._keyfile.textChanged.connect(
            lambda t: self._verify_btn.setEnabled(bool(t.strip())))
        passph_row = QWidget()
        passph_hl = QHBoxLayout(passph_row); passph_hl.setContentsMargins(0, 0, 0, 0)
        passph_hl.addWidget(self._passphrase)
        passph_hl.addWidget(self._verify_btn)
        passph_hl.addWidget(self._verify_lbl)
        auth_form.addRow(self._use_agent)
        auth_form.addRow('Password:', self._password)
        auth_form.addRow('Key file:', key_row)
        auth_form.addRow('Passphrase:', passph_row)
        main_layout.addWidget(auth_box)

        # ---- Forwarding type ----
        fwd_box = QGroupBox('Forwarding')
        fwd_layout = QVBoxLayout(fwd_box)
        type_row = QHBoxLayout()
        self._rb_dynamic = QRadioButton('Dynamic (SOCKS5)')
        self._rb_local   = QRadioButton('Local (-L)')
        self._rb_remote  = QRadioButton('Remote (-R)')
        self._rb_dynamic.setChecked(True)
        for rb in (self._rb_dynamic, self._rb_local, self._rb_remote):
            type_row.addWidget(rb)
            rb.toggled.connect(self._on_type_changed)
        fwd_layout.addLayout(type_row)

        fwd_form = QFormLayout()
        self._bind_addr = QLineEdit('127.0.0.1')
        self._bind_port = QSpinBox(); self._bind_port.setRange(1, 65535); self._bind_port.setValue(2226)
        self._lbl_dest_host = QLabel('Remote host:')
        self._dest_host = QLineEdit()
        self._lbl_dest_port = QLabel('Remote port:')
        self._dest_port = QSpinBox(); self._dest_port.setRange(1, 65535); self._dest_port.setValue(80)
        fwd_form.addRow('Bind addr:', self._bind_addr)
        fwd_form.addRow('Bind port:', self._bind_port)
        fwd_form.addRow(self._lbl_dest_host, self._dest_host)
        fwd_form.addRow(self._lbl_dest_port, self._dest_port)
        fwd_layout.addLayout(fwd_form)
        main_layout.addWidget(fwd_box)

        # ---- Proxy ----
        proxy_box = QGroupBox('Proxy (optional)')
        proxy_form = QFormLayout(proxy_box)
        self._proxy_type = QComboBox()
        self._proxy_type.addItems(self._PROXY_TYPES)
        self._proxy_host = QLineEdit()
        self._proxy_port = QSpinBox(); self._proxy_port.setRange(1, 65535); self._proxy_port.setValue(1080)
        self._proxy_user = QLineEdit()
        self._proxy_pass = QLineEdit(); self._proxy_pass.setEchoMode(QLineEdit.EchoMode.Password)
        proxy_form.addRow('Type:', self._proxy_type)
        proxy_form.addRow('Host:', self._proxy_host)
        proxy_form.addRow('Port:', self._proxy_port)
        proxy_form.addRow('Username:', self._proxy_user)
        proxy_form.addRow('Password:', self._proxy_pass)
        if has_parent:
            proxy_box.setEnabled(False)
            proxy_box.setTitle('Proxy (inherited from parent)')
        main_layout.addWidget(proxy_box)

        # ---- Connection options ----
        opt_box = QGroupBox('Connection options')
        opt_form = QFormLayout(opt_box)
        self._keepalive = QSpinBox(); self._keepalive.setRange(0, 3600); self._keepalive.setValue(30)
        self._keepalive.setSuffix(' s (0 = disabled)')
        self._auto_reconnect = QCheckBox('Auto-reconnect on disconnect')
        self._auto_reconnect.setChecked(True)
        opt_form.addRow('Keepalive interval:', self._keepalive)
        opt_form.addRow(self._auto_reconnect)
        main_layout.addWidget(opt_box)

        # ---- Buttons ----
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self._accept)
        btns.rejected.connect(self.reject)
        main_layout.addWidget(btns)

        self._on_type_changed()  # Set initial visibility

        if locked:
            for widget in (ssh_box, auth_box, fwd_box, proxy_box, self._keepalive):
                widget.setEnabled(False)

        # ---- Pre-fill from initial ----
        if initial:
            self._name.setText(name or '')
            self._auto_start.setChecked(initial.get('auto_start', True))
            self._host.setText(initial.get('host', ''))
            self._port.setValue(initial.get('port', 22))
            self._user.setText(initial.get('username', ''))
            self._use_agent.setChecked(initial.get('use_agent', True))
            self._password.setText(initial.get('password') or '')
            self._keyfile.setText(initial.get('keyfile') or '')
            self._passphrase.setText(initial.get('passphrase') or '')
            ft = initial.get('forward_type', 'dynamic')
            if ft == 'local':   self._rb_local.setChecked(True)
            elif ft == 'remote': self._rb_remote.setChecked(True)
            else:                self._rb_dynamic.setChecked(True)
            self._bind_addr.setText(initial.get('bind_addr', '127.0.0.1'))
            self._bind_port.setValue(initial.get('bind_port', 2226))
            self._dest_host.setText(initial.get('remote_host', ''))
            if initial.get('remote_port'):
                self._dest_port.setValue(int(initial['remote_port']))
            proxy = initial.get('proxy')
            if proxy:
                ptype = proxy.get('proxy_type', 'socks5').lower()
                idx = self._PROXY_TYPES.index(ptype) if ptype in self._PROXY_TYPES else 0
                self._proxy_type.setCurrentIndex(idx)
                self._proxy_host.setText(proxy.get('addr', ''))
                self._proxy_port.setValue(int(proxy.get('port', 1080)))
                self._proxy_user.setText(proxy.get('username', ''))
                self._proxy_pass.setText(proxy.get('password', ''))
            self._keepalive.setValue(initial.get('keepalive_interval', 30))
            self._auto_reconnect.setChecked(initial.get('auto_reconnect', True))
        elif hasattr(parent, 'profiles'):
            self._name.setText(f'profile_{len(parent.profiles)+1}')  # type: ignore[union-attr]

    def _browse_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, 'Select private key')
        if path:
            self._keyfile.setText(path)

    def _verify_passphrase(self) -> None:
        keyfile = self._keyfile.text().strip()
        passphrase = self._passphrase.text() or None
        try:
            _load_private_key(keyfile, passphrase)
            self._verify_lbl.setText('✓ OK')
            self._verify_lbl.setStyleSheet('color: green;')
        except paramiko.ssh_exception.PasswordRequiredException:
            self._verify_lbl.setText('✗ passphrase required')
            self._verify_lbl.setStyleSheet('color: red;')
        except Exception as exc:
            self._verify_lbl.setText(f'✗ {exc}')
            self._verify_lbl.setStyleSheet('color: red;')

    def _on_type_changed(self) -> None:
        show = self._rb_local.isChecked() or self._rb_remote.isChecked()
        self._dest_host.setVisible(show)
        self._lbl_dest_host.setVisible(show)
        self._dest_port.setVisible(show)
        self._lbl_dest_port.setVisible(show)
        if self._rb_remote.isChecked():
            self._lbl_dest_host.setText('Local target host:')
            self._lbl_dest_port.setText('Local target port:')
        else:
            self._lbl_dest_host.setText('Remote host:')
            self._lbl_dest_port.setText('Remote port:')

    def _accept(self) -> None:
        if not self._host.text().strip() or not self._user.text().strip():
            QMessageBox.warning(self, 'Error', 'Host and username are required.')
            return
        if (self._rb_local.isChecked() or self._rb_remote.isChecked()) and not self._dest_host.text().strip():
            QMessageBox.warning(self, 'Error', 'Destination host is required for this forward type.')
            return
        self.accept()

    @property
    def result_dict(self) -> Dict[str, Any]:
        if self._rb_local.isChecked():    ft = 'local'
        elif self._rb_remote.isChecked(): ft = 'remote'
        else:                             ft = 'dynamic'
        proxy_host = self._proxy_host.text().strip()
        if not self._proxy_host.isEnabled() or not proxy_host:
            proxy: Optional[Dict[str, Any]] = None
        else:
            proxy = {
                'proxy_type': self._proxy_type.currentText(),
                'addr':       proxy_host,
                'port':       self._proxy_port.value(),
                'username':   self._proxy_user.text().strip() or None,
                'password':   self._proxy_pass.text() or None,
            }
        return {
            'name':               self._name.text().strip(),
            'auto_start':         self._auto_start.isChecked(),
            'host':               self._host.text().strip(),
            'port':               self._port.value(),
            'username':           self._user.text().strip(),
            'use_agent':          self._use_agent.isChecked(),
            'password':           self._password.text() or None,
            'keyfile':            self._keyfile.text().strip() or None,
            'passphrase':         self._passphrase.text() or None,
            'forward_type':       ft,
            'bind_addr':          self._bind_addr.text().strip() or '127.0.0.1',
            'bind_port':          self._bind_port.value(),
            'remote_host':        self._dest_host.text().strip(),
            'remote_port':        self._dest_port.value(),
            'proxy':              proxy,
            'keepalive_interval': self._keepalive.value(),
            'auto_reconnect':     self._auto_reconnect.isChecked(),
        }


class ProxyDialog(QDialog):
    _TYPES = ['socks5', 'socks4', 'http']

    def __init__(self, parent: Optional[QWidget] = None,
                 initial: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle('Proxy Configuration')
        self.setModal(True)

        layout = QFormLayout(self)
        layout.setContentsMargins(16, 16, 16, 8)

        self._type = QComboBox()
        self._type.addItems(self._TYPES)
        layout.addRow('Proxy type:', self._type)

        self._host = QLineEdit()
        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(1080)
        self._user = QLineEdit()
        self._pass = QLineEdit()
        self._pass.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow('Proxy host:', self._host)
        layout.addRow('Proxy port:', self._port)
        layout.addRow('Username:', self._user)
        layout.addRow('Password:', self._pass)

        if initial:
            ptype = initial.get('proxy_type', 'socks5').lower()
            idx = self._TYPES.index(ptype) if ptype in self._TYPES else 0
            self._type.setCurrentIndex(idx)
            self._host.setText(initial.get('addr', ''))
            self._port.setValue(int(initial.get('port', 1080)))
            self._user.setText(initial.get('username', ''))
            self._pass.setText(initial.get('password', ''))

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self._accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def _accept(self) -> None:
        if not self._host.text().strip():
            QMessageBox.warning(self, 'Error', 'Proxy host is required.')
            return
        self.accept()

    @property
    def result_dict(self) -> Dict[str, Any]:
        return {
            'proxy_type': self._type.currentText(),
            'addr':       self._host.text().strip(),
            'port':       self._port.value(),
            'username':   self._user.text().strip() or None,
            'password':   self._pass.text() or None,
        }


class ImportConflictDialog(QDialog):
    """Per-conflict choice: replace (checked) or skip (unchecked), with diff view."""

    _DIFF_FIELDS: List[tuple] = [
        ('host',               'SSH host'),
        ('port',               'SSH port'),
        ('username',           'Username'),
        ('forward_type',       'Type'),
        ('bind_addr',          'Bind addr'),
        ('bind_port',          'Bind port'),
        ('remote_host',        'Remote host'),
        ('remote_port',        'Remote port'),
        ('use_agent',          'SSH agent'),
        ('password',           'Password'),
        ('keyfile',            'Key file'),
        ('passphrase',         'Passphrase'),
        ('auto_reconnect',     'Auto-reconnect'),
        ('keepalive_interval', 'Keepalive (s)'),
    ]

    @staticmethod
    def _fmt(key: str, val: Any) -> str:
        if key in ('password', 'passphrase'):
            return '(set)' if val else '(not set)'
        if val is None or val == '':
            return '—'
        return str(val)

    @classmethod
    def _build_diff(cls, existing: Dict[str, Any],
                    imported: Dict[str, Any]) -> str:
        changed:   List[str] = []
        unchanged: List[str] = []
        col = 22

        for key, label in cls._DIFF_FIELDS:
            fe = cls._fmt(key, existing.get(key))
            fi = cls._fmt(key, imported.get(key))
            if fe != fi:
                changed.append(f'  {label:<{col}} {fe}  →  {fi}')
            else:
                unchanged.append(f'  {label:<{col}} {fe}')

        # proxy
        def proxy_str(cfg: Dict[str, Any]) -> str:
            p = cfg.get('proxy') or {}
            if not p.get('addr'):
                return '—'
            auth = f' ({p["username"]}@)' if p.get('username') else ''
            return f"{p.get('proxy_type','socks5')} {p['addr']}:{p.get('port',1080)}{auth}"

        pe, pi = proxy_str(existing), proxy_str(imported)
        label = 'Proxy'
        if pe != pi:
            changed.append(f'  {label:<{col}} {pe}  →  {pi}')
        else:
            unchanged.append(f'  {label:<{col}} {pe}')

        parts: List[str] = []
        if changed:
            parts.append('Changed:\n' + '\n'.join(changed))
        if unchanged:
            parts.append('Unchanged:\n' + '\n'.join(unchanged))
        return '\n\n'.join(parts) if parts else '(identical)'

    def __init__(self, parent: Optional[QWidget], conflicts: List[str],
                 total: int,
                 existing: Optional[Dict[str, Any]] = None,
                 imported: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(parent)
        self._existing = existing or {}
        self._imported = imported or {}

        self.setWindowTitle('Import — conflicts')
        self.setModal(True)
        self.setMinimumSize(700, 420)
        self.resize(820, 500)

        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(12, 12, 12, 8)

        lbl = QLabel(
            f'<b>{total}</b> profile(s) to import, '
            f'<b>{len(conflicts)}</b> already exist.<br>'
            'Check the profiles you want to <b>replace</b>; uncheck to skip.'
        )
        vbox.addWidget(lbl)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left — checklist
        left = QWidget()
        left_vbox = QVBoxLayout(left)
        left_vbox.setContentsMargins(0, 0, 4, 0)
        left_vbox.addWidget(QLabel('Conflicts:'))
        self._list = QListWidget()
        self._list.setMinimumWidth(180)
        for name in conflicts:
            item = QListWidgetItem(name)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            self._list.addItem(item)
        self._list.currentRowChanged.connect(self._on_selection)
        left_vbox.addWidget(self._list)

        btn_row = QHBoxLayout()
        all_btn  = QPushButton('Check all')
        none_btn = QPushButton('Uncheck all')
        all_btn.clicked.connect(lambda: self._set_all(Qt.CheckState.Checked))
        none_btn.clicked.connect(lambda: self._set_all(Qt.CheckState.Unchecked))
        btn_row.addWidget(all_btn)
        btn_row.addWidget(none_btn)
        left_vbox.addLayout(btn_row)
        splitter.addWidget(left)

        # Right — diff panel
        right = QWidget()
        right_vbox = QVBoxLayout(right)
        right_vbox.setContentsMargins(4, 0, 0, 0)
        right_vbox.addWidget(QLabel('Differences (existing  →  imported):'))
        self._diff = QPlainTextEdit()
        self._diff.setReadOnly(True)
        self._diff.setFont(self._diff.document().defaultFont())
        right_vbox.addWidget(self._diff)
        splitter.addWidget(right)

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        vbox.addWidget(splitter, 1)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        vbox.addWidget(btns)

        if self._list.count():
            self._list.setCurrentRow(0)

    def _on_selection(self, row: int) -> None:
        if row < 0:
            self._diff.setPlainText('')
            return
        name = self._list.item(row).text()
        ex = self._existing.get(name, {})
        im = self._imported.get(name, {})
        self._diff.setPlainText(self._build_diff(ex, im))

    def _set_all(self, state: Qt.CheckState) -> None:
        for i in range(self._list.count()):
            self._list.item(i).setCheckState(state)

    @property
    def to_replace(self) -> List[str]:
        return [
            self._list.item(i).text()
            for i in range(self._list.count())
            if self._list.item(i).checkState() == Qt.CheckState.Checked
        ]


class LogFileDialog(QDialog):
    """Configure file logging for connection debugging."""

    LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR']

    def __init__(self, parent: Optional[QWidget] = None,
                 initial: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle('Log File')
        self.setModal(True)
        self.setMinimumWidth(420)

        layout = QFormLayout(self)
        layout.setContentsMargins(16, 16, 16, 8)

        self._enabled = QCheckBox('Write logs to file')
        layout.addRow(self._enabled)

        self._path = QLineEdit()
        self._path.setPlaceholderText('ssh_tunnel.log')
        browse = QPushButton('Browse…')
        browse.setFixedWidth(80)
        browse.clicked.connect(self._browse)
        path_row = QWidget()
        hl = QHBoxLayout(path_row); hl.setContentsMargins(0, 0, 0, 0)
        hl.addWidget(self._path); hl.addWidget(browse)
        layout.addRow('Log file:', path_row)

        self._level = QComboBox()
        self._level.addItems(self.LEVELS)
        layout.addRow('Log level:', self._level)

        self._max_mb = QSpinBox()
        self._max_mb.setRange(1, 500)
        self._max_mb.setValue(10)
        self._max_mb.setSuffix(' MB')
        layout.addRow('Max file size:', self._max_mb)

        self._backups = QSpinBox()
        self._backups.setRange(0, 20)
        self._backups.setValue(3)
        self._backups.setSuffix(' backup(s)')
        layout.addRow('Keep:', self._backups)

        if initial:
            self._enabled.setChecked(initial.get('log_file_enabled', False))
            self._path.setText(initial.get('log_file_path', ''))
            lvl = initial.get('log_level', 'INFO')
            idx = self.LEVELS.index(lvl) if lvl in self.LEVELS else 1
            self._level.setCurrentIndex(idx)
            self._max_mb.setValue(initial.get('log_max_mb', 10))
            self._backups.setValue(initial.get('log_backups', 3))

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self._accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def _browse(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, 'Select log file', self._path.text() or 'ssh_tunnel.log',
            'Log files (*.log);;All files (*)',
        )
        if path:
            self._path.setText(path)

    def _accept(self) -> None:
        if self._enabled.isChecked() and not self._path.text().strip():
            QMessageBox.warning(self, 'Error', 'Please specify a log file path.')
            return
        self.accept()

    @property
    def result_dict(self) -> Dict[str, Any]:
        return {
            'log_file_enabled': self._enabled.isChecked(),
            'log_file_path':    self._path.text().strip(),
            'log_level':        self._level.currentText(),
            'log_max_mb':       self._max_mb.value(),
            'log_backups':      self._backups.value(),
        }
