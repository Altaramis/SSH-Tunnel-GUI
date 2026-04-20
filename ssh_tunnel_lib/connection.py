# Copyright (C) 2026  Altaramis
# SPDX-License-Identifier: GPL-3.0-or-later
"""SSH connection lifecycle."""

import logging
from typing import Optional

import paramiko

from ssh_tunnel_lib.handlers import open_ssh_socket
from ssh_tunnel_lib.tunnel_config import TunnelConfig

logger = logging.getLogger('ssh_tunnel_lib')

_KEY_CLASSES = (
    paramiko.RSAKey,
    paramiko.ECDSAKey,
    paramiko.Ed25519Key,
)


def _load_private_key(
    filename: str, passphrase: Optional[str]
) -> paramiko.PKey:
    """Try each key class in order; raise on failure."""
    last_exc: Optional[Exception] = None
    for klass in _KEY_CLASSES:
        try:
            return klass.from_private_key_file(filename, password=passphrase)
        except paramiko.ssh_exception.PasswordRequiredException:
            raise
        except Exception as exc:
            last_exc = exc
            continue
    detail = str(last_exc) if last_exc else "unsupported format"
    if passphrase is not None:
        raise paramiko.ssh_exception.SSHException(
            f"Could not load key file {filename!r}: wrong passphrase or unsupported format ({detail})"
        )
    raise paramiko.ssh_exception.SSHException(
        f"Could not load key file {filename!r}: {detail}"
    )


class SSHConnection:
    """Wraps a paramiko SSHClient; exposes transport and connection-state helpers."""

    def __init__(self, client: paramiko.SSHClient) -> None:
        self._client    = client
        self._transport = client.get_transport()

    @classmethod
    def open(cls, config: TunnelConfig, timeout: float = 10.0) -> 'SSHConnection':
        """Establish an SSH connection as described by *config*."""
        sock = open_ssh_socket(config.hostname, config.port, config.proxy, timeout)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        pkey: Optional[paramiko.PKey] = None
        if config.key_filename:
            pkey = _load_private_key(config.key_filename, config.passphrase)

        client.connect(
            config.hostname, config.port, config.username,
            password=config.password,
            pkey=pkey,
            key_filename=None,
            passphrase=config.passphrase,
            timeout=timeout,
            sock=sock,
            allow_agent=config.allow_agent,
            look_for_keys=config.look_for_keys,
        )

        transport = client.get_transport()
        if config.keepalive_interval > 0 and transport is not None:
            transport.set_keepalive(config.keepalive_interval)

        logger.debug(
            "SSH connection established: %s@%s:%d",
            config.username, config.hostname, config.port,
        )
        return cls(client)

    @property
    def transport(self) -> Optional[paramiko.Transport]:
        return self._transport

    @property
    def is_active(self) -> bool:
        return self._transport is not None and self._transport.is_active()

    def close(self) -> None:
        try:
            if self._transport is not None:
                self._transport.close()
        except Exception:
            pass
        try:
            self._client.close()
        except Exception:
            pass
