# Copyright (C) 2026  Altaramis
# SPDX-License-Identifier: GPL-3.0-or-later
"""Master-password encryption using PBKDF2-SHA256 + Fernet."""

import os
import base64
import logging
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    import keyring as _keyring
    KEYRING_AVAILABLE = True
except ImportError:
    _keyring = None  # type: ignore[assignment]
    KEYRING_AVAILABLE = False

KEYRING_SERVICE = 'ssh_tunnel_gui'
KEYRING_USERNAME = 'master_password'

logger = logging.getLogger('ssh_tunnel_table')


class EncryptionManager:
    # Kept for migration: files written before random-salt support still decrypt correctly.
    _DEFAULT_SALT = b'a_unique_and_secure_salt_for_your_app'

    def __init__(self, master_password: Optional[str] = None, salt: Optional[bytes] = None):
        self.master_password = master_password
        self._fernet: Optional[Fernet] = None
        self._salt: bytes = salt if salt is not None else self._DEFAULT_SALT

    def _get_key(self, password: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=480_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def set_password(self, password: str) -> None:
        self.master_password = password
        self._fernet = Fernet(self._get_key(password))

    def set_salt(self, salt: bytes) -> None:
        """Replace the PBKDF2 salt and re-derive the key if a password is already set."""
        self._salt = salt
        if self.master_password:
            self.set_password(self.master_password)

    def encrypt(self, data: str) -> str:
        if not self._fernet:
            raise ValueError("Master password not set")
        return '' if not data else self._fernet.encrypt(data.encode()).decode()

    def decrypt(self, data: str) -> str:
        """Raises InvalidToken if the key is wrong or data is corrupted."""
        if not self._fernet:
            raise ValueError("Master password not set")
        return '' if not data else self._fernet.decrypt(data.encode()).decode()

    # ---- Keyring helpers ----

    def load_from_keyring(self) -> tuple[Optional[str], bool]:
        if not KEYRING_AVAILABLE:
            return None, False
        try:
            pwd = _keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
            return (pwd, True) if pwd else (None, False)
        except Exception:
            logger.warning("Failed to read master password from keyring.")
            return None, False

    def save_to_keyring(self, password: Optional[str], remember: bool) -> None:
        if not KEYRING_AVAILABLE:
            return
        try:
            if remember and password:
                _keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, password)
            else:
                try:
                    _keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
                except Exception:
                    pass
        except Exception:
            logger.exception("Failed to update keyring.")

    # ---- Random-salt migration ----

    @staticmethod
    def random_salt() -> bytes:
        return os.urandom(16)
