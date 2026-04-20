# Copyright (C) 2026  Altaramis
# SPDX-License-Identifier: GPL-3.0-or-later
"""Main window and application logic (PyQt6)."""

import base64
import json
import logging
import logging.handlers
import os
import threading
import time
from typing import Any, Deque, Dict, List, Optional

from PyQt6.QtCore import QPoint, QTimer, Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QCursor, QPalette, QPen, QPolygon
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog,
    QFileDialog, QHBoxLayout, QHeaderView, QInputDialog, QLabel,
    QLineEdit, QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QProxyStyle,
    QPushButton, QStatusBar, QStyle, QStyledItemDelegate, QTreeWidget,
    QTreeWidgetItem, QVBoxLayout, QWidget,
)

from cryptography.fernet import InvalidToken

from ssh_tunnel_lib import SSHManager, TunnelConfig
from ssh_tunnel_gui.encryption import EncryptionManager
from ssh_tunnel_gui.log_handler import LOG_FORMAT, attach_buffer, make_log_buffer
from ssh_tunnel_gui.dialogs import (
    ChangeMasterPasswordDialog, ImportConflictDialog, LogFileDialog,
    MasterPasswordDialog, ProxyDialog, TunnelConfigDialog,
)

PROFILE_FILE = 'ssh_profiles.json'
CONFIG_FILE  = 'ssh_tunnel_config.json'
LOGGER = logging.getLogger('ssh_tunnel_table')
_RECONNECT_DELAYS = [5, 10, 30, 60]

_COL_HEADERS = ['Name', 'Type', 'Auto', '', 'Bind Port', '⇄', 'Target', 'SSH Server', 'Proxy', '⚙']
_COL_WIDTHS   = [ 200,   80,    60,  140,   150,       40,   200,     200,          150,    60]
#                  ^0 tree       ^2auto ^3act            ^5arrow
_COL_ACT   = 3
_COL_ARROW = 5

# Alternating group background colors per theme
_GROUP_PALETTES: Dict[str, list] = {
    'Light': [QColor('#c0d0ff'), QColor('#ddc0ff')],  # blue / lavender
    'Dark':  [QColor('#182440'), QColor('#28183c')],  # dark blue / dark violet
}


def _depth_tint(base: QColor, depth: int, is_dark: bool) -> QColor:
    """Slightly darken (light theme) or lighten (dark theme) by depth level."""
    if depth == 0:
        return base
    h, s, l, a = base.getHsl()
    step = 14
    l = min(255, l + depth * step) if is_dark else max(0, l - depth * step)
    c = QColor()
    c.setHsl(h, s, l, a)
    return c


class _BranchStyle(QProxyStyle):
    """Draws tree branch lines and expand/collapse arrows via QPainter."""

    def __init__(self, line_color: QColor, arrow_color: QColor) -> None:
        super().__init__()
        self._line_pen    = QPen(line_color, 1)
        self._arrow_brush = QBrush(arrow_color)

    def drawPrimitive(self, element, option, painter, widget=None) -> None:
        if element != QStyle.PrimitiveElement.PE_IndicatorBranch:
            super().drawPrimitive(element, option, painter, widget)
            return

        S  = QStyle.StateFlag
        st = option.state
        rc = option.rect
        cx = rc.center().x()
        cy = rc.center().y()

        has_sib = bool(st & S.State_Sibling)
        has_ch  = bool(st & S.State_Children)
        is_item = bool(st & S.State_Item)
        is_open = bool(st & S.State_Open)

        painter.save()
        painter.setRenderHint(painter.RenderHint.Antialiasing, False)
        painter.setPen(self._line_pen)

        if has_sib:
            painter.drawLine(cx, rc.top(), cx, rc.bottom())
        elif is_item:
            painter.drawLine(cx, rc.top(), cx, cy)

        if is_item:
            painter.drawLine(cx, cy, rc.right(), cy)

        if has_ch:
            painter.setRenderHint(painter.RenderHint.Antialiasing, True)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(self._arrow_brush)
            if is_open:
                poly = QPolygon([QPoint(cx - 4, cy - 2),
                                  QPoint(cx + 4, cy - 2),
                                  QPoint(cx,     cy + 3)])
            else:
                poly = QPolygon([QPoint(cx - 2, cy - 4),
                                  QPoint(cx + 3, cy),
                                  QPoint(cx - 2, cy + 4)])
            painter.drawPolygon(poly)

        painter.restore()


_BG = {
    'active':       QBrush(QColor('#c8f7c8')),
    'reconnecting': QBrush(QColor('#ffe0a0')),
    'error':        QBrush(QColor('#ffc8c8')),
}
_FG_DARK = QBrush(QColor('#000000'))


def _make_dark_palette() -> QPalette:
    p = QPalette()
    c = p.setColor
    c(QPalette.ColorRole.Window,          QColor(45,  45,  45))
    c(QPalette.ColorRole.WindowText,      QColor(220, 220, 220))
    c(QPalette.ColorRole.Base,            QColor(30,  30,  30))
    c(QPalette.ColorRole.AlternateBase,   QColor(45,  45,  45))
    c(QPalette.ColorRole.ToolTipBase,     QColor(45,  45,  45))
    c(QPalette.ColorRole.ToolTipText,     QColor(220, 220, 220))
    c(QPalette.ColorRole.Text,            QColor(220, 220, 220))
    c(QPalette.ColorRole.Button,          QColor(60,  60,  60))
    c(QPalette.ColorRole.ButtonText,      QColor(220, 220, 220))
    c(QPalette.ColorRole.BrightText,      QColor(255, 255, 255))
    c(QPalette.ColorRole.Link,            QColor(80,  160, 240))
    c(QPalette.ColorRole.Highlight,       QColor(60,  120, 210))
    c(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
    c(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text,       QColor(120, 120, 120))
    c(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(120, 120, 120))
    c(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor(120, 120, 120))
    return p


def _make_light_palette() -> QPalette:
    p = QPalette()
    c = p.setColor
    c(QPalette.ColorRole.Window,          QColor(240, 240, 240))
    c(QPalette.ColorRole.WindowText,      QColor(0,   0,   0))
    c(QPalette.ColorRole.Base,            QColor(255, 255, 255))
    c(QPalette.ColorRole.AlternateBase,   QColor(233, 233, 233))
    c(QPalette.ColorRole.ToolTipBase,     QColor(255, 255, 220))
    c(QPalette.ColorRole.ToolTipText,     QColor(0,   0,   0))
    c(QPalette.ColorRole.Text,            QColor(0,   0,   0))
    c(QPalette.ColorRole.Button,          QColor(240, 240, 240))
    c(QPalette.ColorRole.ButtonText,      QColor(0,   0,   0))
    c(QPalette.ColorRole.BrightText,      QColor(255, 0,   0))
    c(QPalette.ColorRole.Link,            QColor(0,   0,   200))
    c(QPalette.ColorRole.Highlight,       QColor(0,   120, 215))
    c(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
    c(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text,       QColor(160, 160, 160))
    c(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(160, 160, 160))
    c(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor(160, 160, 160))
    return p


class _ActionHeaderView(QHeaderView):
    """Header that aligns ↺ / Action / ⏱ with the col-4 cell widget zones."""
    _MARGIN  = 2
    _SPACING = 3
    _RETRY_W = 28
    _CD_W    = 35
    _COL     = _COL_ACT

    def paintSection(self, painter, rect, logical_index: int) -> None:
        super().paintSection(painter, rect, logical_index)
        if logical_index != self._COL:
            return
        w  = rect.width()
        m  = self._MARGIN
        sp = self._SPACING
        rw = self._RETRY_W
        cw = self._CD_W
        retry_r     = rect.adjusted(m,           0, -(w - m - rw),  0)
        action_r    = rect.adjusted(m + rw + sp, 0, -(m + cw + sp), 0)
        countdown_r = rect.adjusted(w - m - cw,  0, -m,             0)
        painter.save()
        painter.setPen(self.palette().buttonText().color())
        painter.drawText(retry_r,     Qt.AlignmentFlag.AlignCenter, '↺')
        painter.drawText(action_r,    Qt.AlignmentFlag.AlignCenter, 'Action')
        painter.drawText(countdown_r, Qt.AlignmentFlag.AlignCenter, '⏱')
        painter.restore()


class _LargerFontDelegate(QStyledItemDelegate):
    def __init__(self, size_pt: int, parent=None) -> None:
        super().__init__(parent)
        self._size = size_pt

    def initStyleOption(self, option, index) -> None:
        super().initStyleOption(option, index)
        option.font.setPointSize(self._size)


def _cell_btn(text: str, bg: Optional[QBrush]) -> QPushButton:
    bg_css = (f"background-color: {bg.color().name()};"
              if bg is not None else "background-color: transparent;")
    fg_css = "color: #000000;" if bg is not None else ""
    btn = QPushButton(text)
    btn.setFlat(True)
    btn.setStyleSheet(f"""
        QPushButton {{
            {bg_css}
            {fg_css}
            border: 1px solid #888888;
            border-radius: 3px;
            padding: 1px 5px;
            font-size: 13px;
            min-width: 0;
        }}
        QPushButton:hover  {{ border-color: #444444; }}
        QPushButton:pressed {{ border-color: #111111; }}
    """)
    return btn


class _TunnelTree(QTreeWidget):
    """QTreeWidget with internal drag-drop for reparenting and reordering profiles."""

    item_dropped = pyqtSignal()
    is_dragging  = False  # class-level flag, read by MainWindow._on_timer

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.setDropIndicatorShown(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setAutoScroll(True)
        self.setAutoScrollMargin(40)
        self._is_running_fn = lambda _name: False

    def startDrag(self, supported_actions) -> None:
        item = self.currentItem()
        if item:
            name = item.data(0, Qt.ItemDataRole.UserRole)
            if name and self._is_running_fn(name):
                return
        _TunnelTree.is_dragging = True
        super().startDrag(supported_actions)
        _TunnelTree.is_dragging = False

    def dragMoveEvent(self, event) -> None:
        super().dragMoveEvent(event)
        y = event.position().y()
        h = self.viewport().height()
        sb = self.verticalScrollBar()
        margin = 40
        if y < margin:
            sb.setValue(sb.value() - max(1, int((margin - y) / 4)))
        elif y > h - margin:
            sb.setValue(sb.value() + max(1, int((y - (h - margin)) / 4)))

    def dropEvent(self, event) -> None:
        super().dropEvent(event)
        _TunnelTree.is_dragging = False
        self.item_dropped.emit()


class MainWindow(QMainWindow):
    """Primary application window."""

    _refresh_requested = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle('SSH Tunnelings')
        self.setMinimumSize(900, 400)

        _app = QApplication.instance()
        self._system_style   = _app.style().objectName()
        self._system_palette = _app.palette()
        self._current_theme  = 'System'

        self.manager = SSHManager()
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self.encryption_manager = EncryptionManager()
        self.master_pwd_ok = False
        self.master_password: Optional[str] = None
        self.remember_master_pwd = False

        self._reconnect_pending: Dict[str, float]  = {}
        self._reconnect_attempts: Dict[str, int]   = {}
        self._reconnect_history: Dict[str, int]    = {}
        self._profile_errors: Dict[str, str]       = {}
        self._collapsed_items: set                 = set()

        self._log_buffer: Deque[str] = make_log_buffer()
        attach_buffer(self._log_buffer)
        self._log_window: Optional[QWidget] = None

        self._last_state_hash: Optional[tuple] = None
        self._refresh_requested.connect(self._repopulate_tree)

        self._config: Dict[str, Any] = {}
        self._file_log_handler: Optional[logging.Handler] = None
        self._load_config()
        self._apply_file_logging()

        self._load_salt_from_file()
        self._show_master_pwd_dialog()

        if self.master_pwd_ok:
            self._load_profiles()
            self._migrate_salt_if_needed()
            self._save_master_pwd_if_needed()
            self._build_ui()
            saved_theme = self._config.get('theme', 'System')
            if saved_theme != 'System':
                self._theme_combo.setCurrentText(saved_theme)
            self._timer = QTimer(self)
            self._timer.timeout.connect(self._on_timer)
            self._timer.start(1000)
        else:
            self._build_locked_ui()

    # ------------------------------------------------------------------ App config / file logging

    def _load_config(self) -> None:
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, encoding='utf-8') as f:
                    self._config = json.load(f)
        except Exception:
            LOGGER.exception('Failed to load config')

    def _save_config(self) -> None:
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2)
        except Exception:
            LOGGER.exception('Failed to save config')

    def _apply_file_logging(self) -> None:
        _loggers = ('ssh_tunnel_lib', 'ssh_tunnel_table')
        if self._file_log_handler is not None:
            for name in _loggers:
                logging.getLogger(name).removeHandler(self._file_log_handler)
            self._file_log_handler.close()
            self._file_log_handler = None

        if not self._config.get('log_file_enabled') or not self._config.get('log_file_path'):
            return

        level   = getattr(logging, self._config.get('log_level', 'INFO'), logging.INFO)
        max_b   = self._config.get('log_max_mb', 10) * 1024 * 1024
        backups = self._config.get('log_backups', 3)
        try:
            handler = logging.handlers.RotatingFileHandler(
                self._config['log_file_path'],
                maxBytes=max_b, backupCount=backups, encoding='utf-8',
            )
            handler.setLevel(level)
            handler.setFormatter(logging.Formatter(LOG_FORMAT))
            for name in _loggers:
                logging.getLogger(name).addHandler(handler)
            self._file_log_handler = handler
            LOGGER.info('File logging active → %s (level=%s)',
                        self._config['log_file_path'],
                        self._config.get('log_level', 'DEBUG'))
        except Exception:
            LOGGER.exception('Failed to start file logging')

    def _configure_log_file(self) -> None:
        dlg = LogFileDialog(self, initial=self._config)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._config.update(dlg.result_dict)
            self._save_config()
            self._apply_file_logging()

    # ------------------------------------------------------------------ Salt

    def _load_salt_from_file(self) -> None:
        if not os.path.exists(PROFILE_FILE):
            return
        try:
            with open(PROFILE_FILE) as f:
                data = json.load(f)
            salt_b64 = data.get('_meta', {}).get('salt')
            if salt_b64:
                self.encryption_manager._salt = base64.b64decode(salt_b64)
        except Exception:
            pass

    def _migrate_salt_if_needed(self) -> None:
        if not os.path.exists(PROFILE_FILE):
            return
        try:
            with open(PROFILE_FILE) as f:
                data = json.load(f)
            if 'salt' not in data.get('_meta', {}):
                self.encryption_manager.set_salt(EncryptionManager.random_salt())
                self._save_profiles()
                LOGGER.info("Migrated to random per-installation PBKDF2 salt.")
        except Exception:
            LOGGER.exception('Failed to migrate PBKDF2 salt')

    # ------------------------------------------------------------------ Master password

    def _show_master_pwd_dialog(self) -> None:
        initial_pwd, remember_state = self.encryption_manager.load_from_keyring()
        dlg = MasterPasswordDialog(self, initial_pwd, remember_state)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            self.master_pwd_ok = False
            return

        self.master_password = dlg.password
        self.remember_master_pwd = dlg.remember
        self.encryption_manager.set_password(self.master_password)

        if not os.path.exists(PROFILE_FILE):
            self.master_pwd_ok = True
            return

        try:
            with open(PROFILE_FILE) as f:
                data = json.load(f)
            verify_token = data.get('_verify')
            if verify_token:
                try:
                    if self.encryption_manager.decrypt(verify_token) == 'ok':
                        self.master_pwd_ok = True
                    else:
                        QMessageBox.critical(self, 'Error', 'Master password invalid.')
                except InvalidToken:
                    QMessageBox.critical(self, 'Error', 'Master password invalid or file corrupted.')
            else:
                self.master_pwd_ok = True
        except Exception as e:
            LOGGER.exception("Failed to validate master password")
            QMessageBox.critical(self, 'Error', f'Master password check failed: {e}')

    def _save_master_pwd_if_needed(self) -> None:
        self.encryption_manager.save_to_keyring(
            self.master_password if self.remember_master_pwd else None,
            self.remember_master_pwd,
        )

    # ------------------------------------------------------------------ Profiles

    def _load_profiles(self) -> None:
        if not os.path.exists(PROFILE_FILE):
            self.profiles = {}
            return
        try:
            with open(PROFILE_FILE) as f:
                raw = json.load(f)
            self.profiles = {}
            for name, cfg in raw.items():
                if name in ('_meta', '_verify'):
                    continue
                dec = cfg.copy()
                for field in ('password', 'passphrase', 'keyfile'):
                    if dec.get(field):
                        try:
                            dec[field] = self.encryption_manager.decrypt(dec[field])
                        except Exception:
                            LOGGER.warning("Could not decrypt '%s' for '%s'", field, name)
                            dec[field] = None
                if dec.get('proxy') and dec['proxy'].get('password'):
                    dec['proxy'] = dec['proxy'].copy()
                    try:
                        dec['proxy']['password'] = self.encryption_manager.decrypt(
                            dec['proxy']['password'])
                    except Exception:
                        LOGGER.warning("Could not decrypt proxy password for '%s'", name)
                        dec['proxy']['password'] = None
                dec.setdefault('auto_start', True)
                dec.setdefault('start_order', 999)
                dec.setdefault('auto_reconnect', True)
                dec.setdefault('keepalive_interval', 30)
                dec.setdefault('parent', None)
                if dec.get('proxy') and 'proxy_type' not in dec['proxy']:
                    dec['proxy']['proxy_type'] = 'socks5'
                self.profiles[name] = dec
            if self._sync_all_child_proxies():
                self._save_profiles()
        except Exception:
            LOGGER.exception('Failed to load profiles')
            QMessageBox.critical(self, 'Error', 'Failed to load profiles. Wrong master password?')
            self.profiles = {}

    def _save_profiles(self) -> None:
        if not self.master_pwd_ok:
            return
        try:
            out: Dict[str, Any] = {
                '_meta':   {'salt': base64.b64encode(self.encryption_manager._salt).decode()},
                '_verify': self.encryption_manager.encrypt('ok'),
            }
            for name, cfg in self.profiles.items():
                enc = cfg.copy()
                for field in ('password', 'passphrase', 'keyfile'):
                    if enc.get(field):
                        enc[field] = self.encryption_manager.encrypt(enc[field])
                if enc.get('proxy') and enc['proxy'].get('password'):
                    enc['proxy'] = enc['proxy'].copy()
                    enc['proxy']['password'] = self.encryption_manager.encrypt(
                        enc['proxy']['password'])
                out[name] = enc
            with open(PROFILE_FILE, 'w') as f:
                json.dump(out, f, indent=2)
        except Exception:
            LOGGER.exception('Failed to save profiles')

    # ------------------------------------------------------------------ UI build

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        vbox = QVBoxLayout(central)
        vbox.setContentsMargins(4, 4, 4, 4)
        vbox.setSpacing(4)

        self.tree = _TunnelTree()
        self.tree._is_running_fn = self._is_profile_running
        self.tree.setHeader(_ActionHeaderView(Qt.Orientation.Horizontal, self.tree))
        self.tree.setHeaderLabels(_COL_HEADERS)
        self.tree.setColumnCount(len(_COL_HEADERS))

        # Larger font for arrow column header
        arrow_header = self.tree.headerItem()
        if arrow_header:
            f = arrow_header.font(_COL_ARROW)
            f.setPointSize(16)
            arrow_header.setFont(_COL_ARROW, f)

        self.tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tree.setAlternatingRowColors(False)
        self.tree.setUniformRowHeights(True)
        self.tree.setRootIsDecorated(True)
        self.tree.setIndentation(18)

        for i, w in enumerate(_COL_WIDTHS):
            self.tree.setColumnWidth(i, w)
        self.tree.setItemDelegateForColumn(_COL_ARROW, _LargerFontDelegate(16, self.tree))

        # Col 0 (Name) stretches with the window; others are user-resizable
        hdr = self.tree.header()
        hdr.setStretchLastSection(False)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, len(_COL_HEADERS)):
            hdr.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)

        self.tree.itemDoubleClicked.connect(self._on_item_double_clicked)
        self.tree.item_dropped.connect(self._on_item_dropped)
        self.tree.itemCollapsed.connect(
            lambda it: self._collapsed_items.add(it.data(0, Qt.ItemDataRole.UserRole)))
        self.tree.itemExpanded.connect(
            lambda it: self._collapsed_items.discard(it.data(0, Qt.ItemDataRole.UserRole)))

        # Right-click anywhere → context menu
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._on_context_menu_requested)
        vbox.addWidget(self.tree)

        # Button bar
        btn_bar = QWidget()
        hbox = QHBoxLayout(btn_bar)
        hbox.setContentsMargins(0, 0, 0, 0)

        def _btn(label: str, slot) -> QPushButton:
            b = QPushButton(label)
            b.clicked.connect(slot)
            return b

        hbox.addWidget(_btn('Add tunnel',       self._add_tunnel))
        hbox.addWidget(_btn('Start all',         self._start_all_profiles))
        hbox.addWidget(_btn('Stop all',          self._stop_all))
        hbox.addWidget(_btn('Export profiles',   self._export_profiles))
        hbox.addWidget(_btn('Import profiles',   self._import_profiles))
        hbox.addStretch()
        hbox.addWidget(QLabel('Theme:'))
        self._theme_combo = QComboBox()
        self._theme_combo.addItems(['System', 'Light', 'Dark'])
        self._theme_combo.currentTextChanged.connect(self._apply_theme)
        hbox.addWidget(self._theme_combo)
        hbox.addWidget(_btn('Logs',              self._toggle_logs_window))
        hbox.addWidget(_btn('Log to file',       self._configure_log_file))
        hbox.addWidget(_btn('Change Master Pwd', self._change_master_password))
        vbox.addWidget(btn_bar)

        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._update_tree_style()
        self._repopulate_tree()
        QTimer.singleShot(0, self._fit_width_to_tree)

    def _update_tree_style(self) -> None:
        theme = self._current_theme
        if theme == 'Dark':
            line_color  = QColor('#6080aa')
            arrow_color = QColor('#aabbcc')
        else:
            line_color  = QColor('#888888')
            arrow_color = QColor('#444444')
        self.tree.setStyle(_BranchStyle(line_color, arrow_color))

    def _fit_width_to_tree(self) -> None:
        total_cols = self.tree.header().length()
        extra = self.width() - self.tree.viewport().width()
        self.resize(total_cols + extra, self.height())

    def _apply_theme(self, mode: str) -> None:
        self._current_theme = mode
        self._config['theme'] = mode
        self._save_config()
        app = QApplication.instance()
        if mode == 'Dark':
            app.setStyle('Fusion')
            app.setPalette(_make_dark_palette())
        elif mode == 'Light':
            app.setStyle('Fusion')
            app.setPalette(_make_light_palette())
        else:
            app.setStyle(self._system_style)
            app.setPalette(self._system_palette)
        if self.master_pwd_ok:
            self._update_tree_style()
            self._repopulate_tree()

    def closeEvent(self, event) -> None:
        if self._log_window is not None:
            self._log_window.close()
        super().closeEvent(event)

    def _build_locked_ui(self) -> None:
        w = QWidget()
        self.setCentralWidget(w)
        vb = QVBoxLayout(w)
        vb.addStretch()
        lbl = QLabel('Application locked — invalid master password.')
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vb.addWidget(lbl)
        btn = QPushButton('Exit')
        btn.clicked.connect(self.close)
        vb.addWidget(btn, alignment=Qt.AlignmentFlag.AlignCenter)
        vb.addStretch()

    # ------------------------------------------------------------------ Tree helpers

    def _build_hierarchy(self) -> tuple[List[str], Dict[str, List[str]]]:
        """Return (roots, children_of) both sorted by start_order."""
        children_of: Dict[str, List[str]] = {}
        roots: List[str] = []
        for name, cfg in self.profiles.items():
            parent = cfg.get('parent')
            if parent and parent in self.profiles:
                children_of.setdefault(parent, []).append(name)
            else:
                roots.append(name)
        roots.sort(key=lambda n: self.profiles[n].get('start_order', 999))
        for lst in children_of.values():
            lst.sort(key=lambda n: self.profiles[n].get('start_order', 999))
        return roots, children_of

    def _build_start_order(self) -> List[str]:
        """DFS traversal: each parent is yielded before its children."""
        roots, children_of = self._build_hierarchy()
        result: List[str] = []

        def dfs(name: str) -> None:
            result.append(name)
            for child in children_of.get(name, []):
                dfs(child)

        for root in roots:
            dfs(root)
        return result

    def _make_tunnel_config(self, prof_name: str, cfg: Dict[str, Any]) -> TunnelConfig:
        """Build a TunnelConfig; children inherit parent bind as SOCKS5 proxy."""
        parent_name = cfg.get('parent')
        if parent_name and parent_name in self.profiles:
            parent_cfg = self.profiles[parent_name]
            proxy: Optional[Dict[str, Any]] = {
                'proxy_type': 'socks5',
                'addr': parent_cfg.get('bind_addr', '127.0.0.1'),
                'port': parent_cfg.get('bind_port', 1080),
            }
        else:
            proxy = cfg.get('proxy')

        return TunnelConfig(
            forward_type=cfg.get('forward_type', 'dynamic'),
            hostname=cfg['host'],
            port=cfg.get('port', 22),
            username=cfg['username'],
            bind_addr=cfg.get('bind_addr', '127.0.0.1'),
            bind_port=cfg.get('bind_port', 2226),
            remote_host=cfg.get('remote_host', ''),
            remote_port=cfg.get('remote_port', 0),
            password=cfg.get('password'),
            key_filename=cfg.get('keyfile'),
            passphrase=cfg.get('passphrase'),
            allow_agent=cfg.get('use_agent', True),
            proxy=proxy,
            keepalive_interval=cfg.get('keepalive_interval', 0),
            name=prof_name,
        )

    def _select_profile(self, prof_name: str) -> None:
        def _search(item: QTreeWidgetItem) -> bool:
            if item.data(0, Qt.ItemDataRole.UserRole) == prof_name:
                self.tree.setCurrentItem(item)
                return True
            for i in range(item.childCount()):
                if _search(item.child(i)):
                    return True
            return False
        for i in range(self.tree.topLevelItemCount()):
            if _search(self.tree.topLevelItem(i)):
                break

    # ------------------------------------------------------------------ Tree population

    def _repopulate_tree(self) -> None:
        scroll_pos = self.tree.verticalScrollBar().value()

        # Save expanded state and selection
        expanded: set = set()
        sel_name: Optional[str] = None
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            name = top.data(0, Qt.ItemDataRole.UserRole)
            if top.isExpanded():
                expanded.add(name)
            if top.isSelected():
                sel_name = name
            for j in range(top.childCount()):
                child = top.child(j)
                cname = child.data(0, Qt.ItemDataRole.UserRole)
                if child.isSelected():
                    sel_name = cname

        self.tree.setUpdatesEnabled(False)
        self.tree.blockSignals(True)
        self.tree.clear()

        roots, children_of = self._build_hierarchy()
        now = time.monotonic()

        if self._current_theme in _GROUP_PALETTES:
            palette_list = _GROUP_PALETTES[self._current_theme]
            is_dark = (self._current_theme == 'Dark')
        else:  # System — detect from palette
            base_lum = QApplication.palette().color(QPalette.ColorRole.Base).lightness()
            is_dark = base_lum < 128
            palette_list = _GROUP_PALETTES['Dark' if is_dark else 'Light']

        def _add_subtree(parent, name: str, base_color: Optional[QColor],
                         parent_color: Optional[QColor],
                         depth: int = 0) -> QTreeWidgetItem:
            node = QTreeWidgetItem()
            if isinstance(parent, QTreeWidgetItem):
                parent.addChild(node)
            else:
                parent.addTopLevelItem(node)
            has_ch = bool(children_of.get(name))
            if depth == 0:
                node_color = base_color
            elif has_ch:
                node_color = _depth_tint(base_color, depth, is_dark) if base_color else None
            else:
                node_color = parent_color  # leaf: same shade as its parent
            self._fill_item(node, name, node_color, now)
            for child_name in children_of.get(name, []):
                _add_subtree(node, child_name, base_color, node_color, depth + 1)
            if node.childCount() > 0 and name not in self._collapsed_items:
                node.setExpanded(True)
            return node

        for group_idx, root_name in enumerate(roots):
            base_color: Optional[QColor] = palette_list[group_idx % len(palette_list)]
            _add_subtree(self.tree, root_name, base_color, base_color)

        self.tree.blockSignals(False)
        self.tree.setUpdatesEnabled(True)

        if sel_name:
            self._select_profile(sel_name)

        self.tree.verticalScrollBar().setValue(scroll_pos)

        running_count = sum(1 for p in self.profiles if self._is_profile_running(p))
        self._status.showMessage(
            f'{len(self.profiles)} profile(s) — {running_count} running'
        )

    def _fill_item(self, item: QTreeWidgetItem, prof_name: str,
                   group_color: Optional[QColor], now: float) -> None:
        cfg = self.profiles[prof_name]
        running      = self._is_profile_running(prof_name)
        reconnecting = prof_name in self._reconnect_pending
        has_error    = prof_name in self._profile_errors

        if running:
            bg, action = _BG['active'],       '⏹'
        elif reconnecting:
            bg, action = _BG['reconnecting'], '↺'
        elif has_error:
            bg, action = _BG['error'],        '▶'
        else:
            bg, action = None,                '▶'

        effective_bg = (bg if bg is not None
                        else (QBrush(group_color) if group_color is not None else None))

        ft = cfg.get('forward_type', 'dynamic')
        if ft == 'local':
            typ   = 'Local (-L)'
            arrow = '→'
            dest  = f"{cfg.get('remote_host','')}:{cfg.get('remote_port','')}"
        elif ft == 'remote':
            typ   = 'Remote (-R)'
            arrow = '←'
            dest  = f"{cfg.get('remote_host','')}:{cfg.get('remote_port','')}"
        else:
            typ   = 'Dynamic'
            arrow = '↠'
            dest  = '*:*'

        bind = f"{cfg.get('bind_addr', '127.0.0.1')}:{cfg.get('bind_port', '')}"

        parent_name = cfg.get('parent')
        if parent_name and parent_name in self.profiles:
            p_cfg = self.profiles[parent_name]
            proxy_str = f"↑ {p_cfg.get('bind_addr','127.0.0.1')}:{p_cfg.get('bind_port','')}"
        else:
            proxy = cfg.get('proxy')
            if proxy and proxy.get('addr'):
                proxy_str = f"{proxy.get('proxy_type', 'socks5')} {proxy['addr']}:{proxy['port']}"
            else:
                proxy_str = '—'

        texts = [
            prof_name,   # 0: Name — tree column (indented to show hierarchy)
            typ,         # 1: Type
            '',          # 2: Auto  (cell widget)
            '',          # 3: Action (cell widget)  _COL_ACT
            bind,        # 4: Bind Port
            arrow,       # 5: ⇄  _COL_ARROW
            dest,        # 6: Target
            f"{cfg.get('username','')}@{cfg.get('host','')}:{cfg.get('port','')}",  # 7
            proxy_str,   # 8: Proxy
            '',          # 9: ⚙ (cell widget)
        ]

        item.setData(0, Qt.ItemDataRole.UserRole, prof_name)
        for col, text in enumerate(texts):
            item.setText(col, text)
            if effective_bg is not None:
                item.setBackground(col, effective_bg)
            if bg is not None:
                item.setForeground(col, _FG_DARK)
            else:
                item.setForeground(col, QBrush())
            if col in (1, _COL_ARROW):
                item.setTextAlignment(col, Qt.AlignmentFlag.AlignCenter)

        # Col 2 — Auto-start toggle
        auto_btn = _cell_btn('✓' if cfg.get('auto_start', True) else '✗', bg)
        auto_btn.clicked.connect(
            lambda _=False, n=prof_name: self._toggle_auto_start(n))
        self.tree.setItemWidget(item, 2, auto_btn)

        # Col 3 — Action compound widget
        attempts  = self._reconnect_attempts.get(prof_name, 0)
        history   = self._reconnect_history.get(prof_name, 0)
        countdown = max(0, int(self._reconnect_pending.get(prof_name, now) - now))
        bg_css    = (f"background-color: {bg.color().name()};"
                     if bg is not None else "background-color: transparent;")
        lbl_style = f"{bg_css}color: #000000;" if bg is not None else ""

        if reconnecting:
            left_text = f'#{attempts}'
        elif running and history > 0:
            left_text = f'⚡{history}'
        else:
            left_text = ''

        retry_lbl = QLabel(left_text)
        retry_lbl.setStyleSheet(lbl_style)
        retry_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        retry_lbl.setFixedWidth(28)

        act_btn = _cell_btn(action, bg)
        if running or reconnecting:
            act_btn.clicked.connect(
                lambda _=False, n=prof_name: self._stop_profile(n))
        else:
            act_btn.clicked.connect(
                lambda _=False, n=prof_name: self._start_profile(n))

        countdown_lbl = QLabel(f'{countdown}s' if reconnecting else '')
        countdown_lbl.setStyleSheet(lbl_style)
        countdown_lbl.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        countdown_lbl.setFixedWidth(35)

        act_container = QWidget()
        act_container.setStyleSheet(bg_css)
        act_hl = QHBoxLayout(act_container)
        act_hl.setContentsMargins(2, 0, 2, 0)
        act_hl.setSpacing(3)
        act_hl.addWidget(retry_lbl)
        act_hl.addWidget(act_btn, 1)
        act_hl.addWidget(countdown_lbl)
        self.tree.setItemWidget(item, _COL_ACT, act_container)

        # Col 9 — Settings gear
        gear_btn = _cell_btn('⚙', bg)
        gear_btn.clicked.connect(
            lambda _=False, n=prof_name: self._show_settings_menu(n))
        self.tree.setItemWidget(item, 9, gear_btn)

    def _is_profile_running(self, profile_name: str) -> bool:
        return any(
            i.get('name') == profile_name and i.get('transport_active', False)
            for i in self.manager.list_instances()
        )

    def _is_ancestor(self, potential_ancestor: str, node: str) -> bool:
        """True if potential_ancestor appears anywhere in node's ancestor chain."""
        visited: set = set()
        current = self.profiles.get(node, {}).get('parent')
        while current and current not in visited:
            if current == potential_ancestor:
                return True
            visited.add(current)
            current = self.profiles.get(current, {}).get('parent')
        return False

    def _sync_child_proxy(self, prof_name: str) -> bool:
        """Set child's stored proxy to parent's bind if different. Returns True if changed."""
        cfg = self.profiles.get(prof_name)
        if not cfg:
            return False
        parent_name = cfg.get('parent')
        if not parent_name or parent_name not in self.profiles:
            return False
        p = self.profiles[parent_name]
        inherited = {
            'proxy_type': 'socks5',
            'addr': p.get('bind_addr', '127.0.0.1'),
            'port': p.get('bind_port', 1080),
        }
        cur = cfg.get('proxy') or {}
        if (cur.get('proxy_type') != inherited['proxy_type'] or
                cur.get('addr') != inherited['addr'] or
                cur.get('port') != inherited['port']):
            cfg['proxy'] = inherited
            return True
        return False

    def _sync_all_child_proxies(self) -> bool:
        """Sync every child's proxy to its parent's bind. Returns True if anything changed."""
        return any(self._sync_child_proxy(n) for n in list(self.profiles))

    def _effective_auto_start(self, prof_name: str) -> bool:
        """True only if this profile AND every ancestor have auto_start enabled."""
        visited: set = set()
        name: Optional[str] = prof_name
        while name and name not in visited:
            cfg = self.profiles.get(name)
            if not cfg or not cfg.get('auto_start', True):
                return False
            visited.add(name)
            name = cfg.get('parent')
        return True

    # ------------------------------------------------------------------ Drag-drop sync

    def _on_item_dropped(self) -> None:
        """Sync profiles from tree after drag-drop; validate that all parents are Dynamic."""
        new_parents: Dict[str, Optional[str]] = {}
        new_orders:  Dict[str, int]           = {}

        def _sync(node: QTreeWidgetItem, parent_name: Optional[str], order: int) -> None:
            name = node.data(0, Qt.ItemDataRole.UserRole)
            if not name:
                return
            effective_parent = parent_name
            if parent_name is not None:
                if self.profiles.get(parent_name, {}).get('forward_type', 'dynamic') != 'dynamic':
                    # Drop onto non-Dynamic: become sibling instead of child
                    effective_parent = self.profiles.get(parent_name, {}).get('parent')
            new_parents[name] = effective_parent
            new_orders[name]  = order
            for i in range(node.childCount()):
                _sync(node.child(i), name, i + 1)

        for top_idx in range(self.tree.topLevelItemCount()):
            _sync(self.tree.topLevelItem(top_idx), None, top_idx + 1)

        for name in new_parents:
            if name in self.profiles:
                self.profiles[name]['parent']      = new_parents[name]
                self.profiles[name]['start_order'] = new_orders[name]

        self._sync_all_child_proxies()
        self._save_profiles()
        self._repopulate_tree()

    # ------------------------------------------------------------------ Click handling

    def _on_item_double_clicked(self, item: QTreeWidgetItem, _col: int) -> None:
        prof_name = item.data(0, Qt.ItemDataRole.UserRole)
        if prof_name:
            self._edit_profile(prof_name)

    # Widget columns — clicking them activates the widget, not the menu
    _WIDGET_COLS = {2, _COL_ACT, 9}

    def _on_context_menu_requested(self, pos) -> None:
        item = self.tree.itemAt(pos)
        if item:
            prof_name = item.data(0, Qt.ItemDataRole.UserRole)
            if prof_name:
                self._show_settings_menu(prof_name)

    def _show_settings_menu(self, prof_name: str) -> None:
        cfg = self.profiles.get(prof_name, {})
        has_parent = bool(cfg.get('parent'))

        menu = QMenu(self)
        menu.addAction('Config',    lambda: self._edit_profile(prof_name))
        act_proxy = menu.addAction('Proxy', lambda: self._edit_proxy(prof_name))
        act_proxy.setEnabled(not has_parent)
        menu.addAction('Duplicate', lambda: self._duplicate_profile(prof_name))
        menu.addSeparator()
        menu.addAction('Set parent…',    lambda: self._set_parent_dialog(prof_name))
        act_remove = menu.addAction('Remove parent', lambda: self._remove_parent(prof_name))
        act_remove.setEnabled(has_parent)
        menu.addSeparator()
        menu.addAction('Move up',   lambda: self._move_up(prof_name))
        menu.addAction('Move down', lambda: self._move_down(prof_name))
        menu.addSeparator()
        menu.addAction('Delete', lambda: self._delete_profile(prof_name))
        menu.exec(QCursor.pos())

    def _toggle_auto_start(self, prof_name: str) -> None:
        cfg = self.profiles.get(prof_name)
        if cfg:
            cfg['auto_start'] = not cfg.get('auto_start', True)
            self._save_profiles()
            self._repopulate_tree()

    def _edit_order(self, prof_name: str) -> None:
        cfg = self.profiles.get(prof_name)
        if cfg:
            val, ok = QInputDialog.getInt(
                self, 'Start order', f'Start order for {prof_name}:',
                value=cfg.get('start_order', 999), min=1, max=999)
            if ok:
                cfg['start_order'] = val
                self._save_profiles()
                self._repopulate_tree()

    # ------------------------------------------------------------------ Profile CRUD

    def _add_tunnel(self) -> None:
        dlg = TunnelConfigDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            r = dlg.result_dict
            name = r.get('name') or f'profile_{len(self.profiles)+1}'
            if name in self.profiles:
                if QMessageBox.question(self, 'Overwrite',
                        f'Profile "{name}" already exists. Overwrite?') != QMessageBox.StandardButton.Yes:
                    return
            r.setdefault('parent', None)
            r.setdefault('start_order', len(self.profiles) + 1)
            self.profiles[name] = r
            self._save_profiles()
            self._repopulate_tree()

    def _edit_profile(self, prof_name: str) -> None:
        cfg = self.profiles.get(prof_name)
        if cfg is None:
            return
        is_running = self._is_profile_running(prof_name)
        dlg = TunnelConfigDialog(self, initial=cfg.copy(), name=prof_name,
                                 has_parent=bool(cfg.get('parent')),
                                 locked=is_running)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            r = dlg.result_dict
            new_name = r.get('name') or prof_name
            if is_running:
                # Only update safe fields — keep connection parameters untouched
                cfg['auto_start']    = r['auto_start']
                cfg['auto_reconnect'] = r['auto_reconnect']
                if new_name != prof_name:
                    for c in self.profiles.values():
                        if c.get('parent') == prof_name:
                            c['parent'] = new_name
                    self.profiles[new_name] = self.profiles.pop(prof_name)
                    self.manager.rename_instance(prof_name, new_name)
            else:
                r.setdefault('parent', cfg.get('parent'))
                r.setdefault('start_order', cfg.get('start_order', 999))
                if new_name != prof_name:
                    for c in self.profiles.values():
                        if c.get('parent') == prof_name:
                            c['parent'] = new_name
                    self.profiles.pop(prof_name, None)
                self.profiles[new_name] = r
                self._sync_all_child_proxies()
            self._save_profiles()
            self._repopulate_tree()

    def _edit_proxy(self, prof_name: str) -> None:
        cfg = self.profiles.get(prof_name)
        if cfg is None:
            return
        dlg = ProxyDialog(self, initial=cfg.get('proxy'))
        if dlg.exec() == QDialog.DialogCode.Accepted:
            cfg['proxy'] = dlg.result_dict
            self._save_profiles()
            self._repopulate_tree()

    def _duplicate_profile(self, prof_name: str) -> None:
        cfg = self.profiles.get(prof_name)
        if cfg is None:
            return
        base = f'{prof_name} (copy)'
        new_name = base
        counter = 2
        while new_name in self.profiles:
            new_name = f'{base} {counter}'
            counter += 1
        dup = cfg.copy()
        dup['parent'] = None  # duplicate is always root-level
        dup['start_order'] = len(self.profiles) + 1
        self.profiles[new_name] = dup
        self._save_profiles()
        self._repopulate_tree()

    def _collect_descendants(self, prof_name: str) -> List[str]:
        """Return all descendants (any depth) of prof_name."""
        result: List[str] = []
        queue = [prof_name]
        while queue:
            current = queue.pop()
            children = [n for n, c in self.profiles.items() if c.get('parent') == current]
            result.extend(children)
            queue.extend(children)
        return result

    def _remove_profile(self, prof_name: str) -> None:
        """Stop and remove a single profile from internal state (no save/repopulate)."""
        if self._is_profile_running(prof_name):
            self._stop_profile(prof_name, _repopulate=False)
        self._reconnect_pending.pop(prof_name, None)
        self._reconnect_attempts.pop(prof_name, None)
        self._reconnect_history.pop(prof_name, None)
        self._profile_errors.pop(prof_name, None)
        self.profiles.pop(prof_name, None)

    def _delete_profile(self, prof_name: str) -> None:
        children = [n for n, c in self.profiles.items() if c.get('parent') == prof_name]
        if children:
            all_desc = self._collect_descendants(prof_name)
            msg = QMessageBox(self)
            msg.setWindowTitle('Delete')
            msg.setText(
                f'Delete "{prof_name}"?\n\n'
                f'It has {len(children)} direct child connection(s)'
                f' ({len(all_desc)} total descendant(s)).'
            )
            btn_with   = msg.addButton('Delete with children',
                                       QMessageBox.ButtonRole.DestructiveRole)
            msg.addButton('Keep children (make root)',
                          QMessageBox.ButtonRole.AcceptRole)
            btn_cancel = msg.addButton(QMessageBox.StandardButton.Cancel)
            msg.setDefaultButton(btn_cancel)
            msg.exec()
            clicked = msg.clickedButton()
            if clicked is btn_cancel or clicked is None:
                return
            if clicked is btn_with:
                for desc in all_desc:
                    self._remove_profile(desc)
            else:  # keep children → make direct children root-level
                for child in children:
                    self.profiles[child]['parent'] = None
        else:
            if QMessageBox.question(self, 'Delete',
                    f'Delete profile "{prof_name}"?') != QMessageBox.StandardButton.Yes:
                return

        self._remove_profile(prof_name)
        self._save_profiles()
        self._repopulate_tree()

    def _set_parent_dialog(self, prof_name: str) -> None:
        candidates = [
            n for n, c in self.profiles.items()
            if n != prof_name
            and c.get('forward_type', 'dynamic') == 'dynamic'
            and not self._is_ancestor(prof_name, n)  # would create a cycle
        ]
        if not candidates:
            QMessageBox.information(self, 'Set parent',
                                    'No Dynamic tunnels available as parent.')
            return
        name, ok = QInputDialog.getItem(
            self, 'Set parent', f'Parent for "{prof_name}":',
            candidates, 0, False)
        if ok and name:
            siblings = [n for n, c in self.profiles.items() if c.get('parent') == name]
            self.profiles[prof_name]['parent']      = name
            self.profiles[prof_name]['start_order'] = len(siblings) + 1
            self._sync_child_proxy(prof_name)
            self._save_profiles()
            self._repopulate_tree()

    def _remove_parent(self, prof_name: str) -> None:
        if prof_name in self.profiles:
            roots = [n for n, c in self.profiles.items() if not c.get('parent')]
            self.profiles[prof_name]['parent']      = None
            self.profiles[prof_name]['start_order'] = len(roots) + 1
            self._save_profiles()
            self._repopulate_tree()

    def _move_up(self, prof_name: str) -> None:
        cfg = self.profiles.get(prof_name)
        if not cfg:
            return
        parent = cfg.get('parent')
        siblings = sorted(
            [n for n, c in self.profiles.items() if c.get('parent') == parent],
            key=lambda n: self.profiles[n].get('start_order', 999),
        )
        idx = siblings.index(prof_name) if prof_name in siblings else -1
        if idx > 0:
            prev = siblings[idx - 1]
            a = self.profiles[prof_name]['start_order']
            b = self.profiles[prev]['start_order']
            self.profiles[prof_name]['start_order'] = b
            self.profiles[prev]['start_order']      = a
            self._save_profiles()
            self._repopulate_tree()

    def _move_down(self, prof_name: str) -> None:
        cfg = self.profiles.get(prof_name)
        if not cfg:
            return
        parent = cfg.get('parent')
        siblings = sorted(
            [n for n, c in self.profiles.items() if c.get('parent') == parent],
            key=lambda n: self.profiles[n].get('start_order', 999),
        )
        idx = siblings.index(prof_name) if prof_name in siblings else -1
        if 0 <= idx < len(siblings) - 1:
            nxt = siblings[idx + 1]
            a = self.profiles[prof_name]['start_order']
            b = self.profiles[nxt]['start_order']
            self.profiles[prof_name]['start_order'] = b
            self.profiles[nxt]['start_order']       = a
            self._save_profiles()
            self._repopulate_tree()

    # ------------------------------------------------------------------ Master password change

    def _change_master_password(self) -> None:
        dlg = ChangeMasterPasswordDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        if dlg.old_password != self.master_password:
            QMessageBox.critical(self, 'Error', 'Current master password is incorrect.')
            return
        old_pwd = self.master_password
        try:
            self.encryption_manager.set_password(dlg.new_password)
            self._save_profiles()
            self.master_password = dlg.new_password
            self._save_master_pwd_if_needed()
            QMessageBox.information(self, 'Success',
                                    'Master password changed and profiles re-encrypted.')
        except Exception as e:
            LOGGER.exception('Failed to change master password')
            self.encryption_manager.set_password(old_pwd)
            QMessageBox.critical(self, 'Error', f'Failed: {e}')

    # ------------------------------------------------------------------ Import / Export

    def _export_profiles(self) -> None:
        if not self.profiles:
            QMessageBox.information(self, 'Export', 'No profiles to export.')
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Export profiles', '',
                                              'JSON files (*.json);;All files (*)')
        if not path:
            return
        try:
            out: Dict[str, Any] = {
                '_meta':   {'salt': base64.b64encode(self.encryption_manager._salt).decode()},
                '_verify': self.encryption_manager.encrypt('ok'),
            }
            for name, cfg in self.profiles.items():
                enc = cfg.copy()
                for field in ('password', 'passphrase', 'keyfile'):
                    if enc.get(field):
                        enc[field] = self.encryption_manager.encrypt(enc[field])
                if enc.get('proxy') and enc['proxy'].get('password'):
                    enc['proxy'] = enc['proxy'].copy()
                    enc['proxy']['password'] = self.encryption_manager.encrypt(
                        enc['proxy']['password'])
                out[name] = enc
            with open(path, 'w') as f:
                json.dump(out, f, indent=2)
            QMessageBox.information(self, 'Export', f'Exported {len(self.profiles)} profile(s).')
        except Exception as e:
            QMessageBox.critical(self, 'Export error', str(e))

    def _import_profiles(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, 'Import profiles', '',
                                              'JSON files (*.json);;All files (*)')
        if not path:
            return
        try:
            with open(path) as f:
                raw = json.load(f)
        except Exception as e:
            QMessageBox.critical(self, 'Import error', f'Cannot read file: {e}')
            return

        import_pwd, ok = QInputDialog.getText(
            self, 'Import password',
            'Master password for the imported file:',
            QLineEdit.EchoMode.Password,
        )
        if not ok or not import_pwd:
            return

        try:
            salt_b64 = raw.get('_meta', {}).get('salt')
            import_salt = base64.b64decode(salt_b64) if salt_b64 else EncryptionManager._DEFAULT_SALT
            em = EncryptionManager(salt=import_salt)
            em.set_password(import_pwd)
            verify = raw.get('_verify')
            if verify and em.decrypt(verify) != 'ok':
                QMessageBox.critical(self, 'Import error', 'Import password invalid.')
                return
        except InvalidToken:
            QMessageBox.critical(self, 'Import error', 'Import password invalid or file corrupted.')
            return
        except Exception as e:
            QMessageBox.critical(self, 'Import error', str(e))
            return

        imported: Dict[str, Any] = {}
        for name, cfg in raw.items():
            if name in ('_meta', '_verify'):
                continue
            dec = cfg.copy()
            for field in ('password', 'passphrase', 'keyfile'):
                if dec.get(field):
                    try:
                        dec[field] = em.decrypt(dec[field])
                    except Exception:
                        dec[field] = None
            if dec.get('proxy') and dec['proxy'].get('password'):
                dec['proxy'] = dec['proxy'].copy()
                try:
                    dec['proxy']['password'] = em.decrypt(dec['proxy']['password'])
                except Exception:
                    dec['proxy']['password'] = None
            dec.setdefault('auto_start', True)
            dec.setdefault('start_order', 999)
            dec.setdefault('auto_reconnect', True)
            dec.setdefault('keepalive_interval', 30)
            dec.setdefault('parent', None)
            if dec.get('proxy') and 'proxy_type' not in dec['proxy']:
                dec['proxy']['proxy_type'] = 'socks5'
            imported[name] = dec

        conflicts = [n for n in imported if n in self.profiles]
        if conflicts:
            dlg = ImportConflictDialog(self, conflicts, len(imported),
                                       existing=self.profiles,
                                       imported=imported)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            to_replace = set(dlg.to_replace)
            imported = {k: v for k, v in imported.items()
                        if k not in conflicts or k in to_replace}
            if not imported:
                return

        self.profiles.update(imported)
        self._save_profiles()
        self._repopulate_tree()
        QMessageBox.information(self, 'Import', f'Imported {len(imported)} profile(s).')

    # ------------------------------------------------------------------ Start / Stop

    def _start_profile(self, prof_name: str, _is_reconnect: bool = False) -> None:
        cfg = self.profiles.get(prof_name)
        if not cfg:
            return

        def worker() -> None:
            try:
                LOGGER.info('%s %s', 'Reconnecting' if _is_reconnect else 'Starting', prof_name)
                config = self._make_tunnel_config(prof_name, cfg)
                self.manager.create_tunnel(config)
                self._profile_errors.pop(prof_name, None)
                self._reconnect_attempts.pop(prof_name, None)
            except Exception as exc:
                LOGGER.error('Failed to start %s: %s', prof_name, exc)
                LOGGER.debug('Failed to start %s', prof_name, exc_info=True)
                if _is_reconnect:
                    attempts = self._reconnect_attempts.get(prof_name, 0) + 1
                    self._reconnect_attempts[prof_name] = attempts
                    delay = _RECONNECT_DELAYS[min(attempts - 1, len(_RECONNECT_DELAYS) - 1)]
                    self._reconnect_pending[prof_name] = time.monotonic() + delay
                    LOGGER.info('Reconnect failed for %s, retry in %ds (attempt %d)',
                                prof_name, delay, attempts)
                else:
                    self._profile_errors[prof_name] = str(exc)
            finally:
                self._refresh_requested.emit()

        threading.Thread(target=worker, daemon=True).start()

    def _stop_profile(self, prof_name: str, _repopulate: bool = True) -> None:
        # Stop children first (reverse connection order)
        children = [n for n, c in self.profiles.items() if c.get('parent') == prof_name]
        for child in children:
            self._stop_profile(child, _repopulate=False)

        self._reconnect_pending.pop(prof_name, None)
        self._reconnect_attempts.pop(prof_name, None)
        self._reconnect_history.pop(prof_name, None)
        self._profile_errors.pop(prof_name, None)
        for info in self.manager.list_instances():
            if info.get('name') == prof_name:
                try:
                    self.manager.close_instance(info['id'])
                    LOGGER.info('Stopped %s', prof_name)
                except Exception as exc:
                    LOGGER.error('Failed to stop %s: %s', prof_name, exc)
                    LOGGER.debug('Failed to stop %s', prof_name, exc_info=True)
        if _repopulate:
            self._repopulate_tree()

    def _start_all_profiles(self) -> None:
        ordered = self._build_start_order()
        to_start = [(n, self.profiles[n]) for n in ordered
                    if self._effective_auto_start(n)]
        if not to_start:
            QMessageBox.information(self, 'Start all', 'No profiles marked for auto-start.')
            return
        if QMessageBox.question(
                self, 'Start all',
                f'Start {len(to_start)} profile(s) in hierarchical order?',
        ) != QMessageBox.StandardButton.Yes:
            return

        def worker() -> None:
            for name, cfg in to_start:
                self._profile_errors.pop(name, None)
                try:
                    LOGGER.info('Starting %s (order %s)', name, cfg.get('start_order'))
                    config = self._make_tunnel_config(name, cfg)
                    self.manager.create_tunnel(config)
                except Exception as exc:
                    LOGGER.error('Failed to start %s: %s', name, exc)
                    LOGGER.debug('Failed to start %s', name, exc_info=True)
                    self._profile_errors[name] = str(exc)
            self._refresh_requested.emit()

        threading.Thread(target=worker, daemon=True).start()

    def _stop_all(self) -> None:
        instances = self.manager.list_instances()
        if not instances:
            QMessageBox.information(self, 'Stop all', 'No active tunnels.')
            return
        if QMessageBox.question(self, 'Stop all',
                'Stop all active tunnels?') != QMessageBox.StandardButton.Yes:
            return
        self._reconnect_pending.clear()
        self._reconnect_attempts.clear()

        # Stop in reverse hierarchical order (children first)
        ordered = list(reversed(self._build_start_order()))

        def worker() -> None:
            for name in ordered:
                for info in self.manager.list_instances():
                    if info.get('name') == name:
                        try:
                            self.manager.close_instance(info['id'])
                            LOGGER.info('Stopped %s', name)
                        except Exception as exc:
                            LOGGER.error('Failed to stop %s: %s', name, exc)
                            LOGGER.debug('Failed to stop %s', name, exc_info=True)
            self._refresh_requested.emit()

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------ Reconnect / timer

    def _state_hash(self) -> tuple:
        running    = frozenset(n for n in self.profiles if self._is_profile_running(n))
        pending    = frozenset(self._reconnect_pending.keys())
        errors     = frozenset(self._profile_errors.keys())
        history    = frozenset(self._reconnect_history.items())
        return (running, pending, errors, history)

    def _on_timer(self) -> None:
        self._check_and_reconnect()
        if _TunnelTree.is_dragging:
            return
        new_hash = self._state_hash()
        if new_hash != self._last_state_hash or self._reconnect_pending:
            self._last_state_hash = new_hash
            self._repopulate_tree()

    def _check_and_reconnect(self) -> None:
        now = time.monotonic()
        for info in self.manager.list_instances():
            if info.get('transport_active', False):
                continue
            prof_name = info.get('name')
            if not prof_name or prof_name not in self.profiles:
                continue
            if prof_name in self._reconnect_pending:
                continue

            LOGGER.warning('Tunnel "%s" disconnected unexpectedly.', prof_name)
            try:
                self.manager.close_instance(info['id'])
            except Exception:
                pass

            cfg = self.profiles[prof_name]
            if not cfg.get('auto_reconnect', True):
                self._profile_errors[prof_name] = 'Disconnected (auto-reconnect disabled)'
                continue

            attempts = self._reconnect_attempts.get(prof_name, 0) + 1
            self._reconnect_attempts[prof_name] = attempts
            self._reconnect_history[prof_name] = self._reconnect_history.get(prof_name, 0) + 1
            delay = _RECONNECT_DELAYS[min(attempts - 1, len(_RECONNECT_DELAYS) - 1)]
            self._reconnect_pending[prof_name] = now + delay
            LOGGER.info('Reconnecting "%s" in %ds (attempt %d)', prof_name, delay, attempts)

        for prof_name, t in list(self._reconnect_pending.items()):
            if now >= t:
                del self._reconnect_pending[prof_name]
                if prof_name in self.profiles:
                    self._start_profile(prof_name, _is_reconnect=True)

    # ------------------------------------------------------------------ Logs window

    def _toggle_logs_window(self) -> None:
        if self._log_window is not None:
            self._log_window.raise_()
            self._log_window.activateWindow()
            return

        win = QWidget(flags=Qt.WindowType.Window)
        win.setWindowTitle('Logs')
        win.setMinimumSize(800, 300)
        win.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        vb = QVBoxLayout(win)

        txt = QPlainTextEdit()
        txt.setReadOnly(True)
        txt.setMaximumBlockCount(2000)
        txt.setPlainText('\n'.join(self._log_buffer))
        vb.addWidget(txt)

        tail_cb = QCheckBox('Tail')
        tail_cb.setChecked(True)

        def _scroll_to_end() -> None:
            txt.verticalScrollBar().setValue(txt.verticalScrollBar().maximum())

        _scroll_to_end()
        tail_cb.toggled.connect(lambda on: _scroll_to_end() if on else None)

        class _LiveHandler(logging.Handler):
            def __init__(self_h) -> None:
                super().__init__()
            def emit(self_h, record: logging.LogRecord) -> None:
                try:
                    txt.appendPlainText(self_h.format(record))
                    if tail_cb.isChecked():
                        _scroll_to_end()
                except Exception:
                    pass

        handler = _LiveHandler()
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        for lg_name in ('ssh_tunnel_lib', 'ssh_tunnel_table'):
            logging.getLogger(lg_name).addHandler(handler)

        def _on_destroyed() -> None:
            for lg_name in ('ssh_tunnel_lib', 'ssh_tunnel_table'):
                logging.getLogger(lg_name).removeHandler(handler)
            self._log_window = None

        win.destroyed.connect(_on_destroyed)

        btn_row = QHBoxLayout()
        btn_row.addWidget(tail_cb)
        btn_row.addStretch()
        close_btn = QPushButton('Close')
        close_btn.clicked.connect(win.close)
        btn_row.addWidget(close_btn)
        vb.addLayout(btn_row)

        self._log_window = win
        win.show()
