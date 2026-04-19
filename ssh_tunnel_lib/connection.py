# Copyright (C) 2026  Altaramis
# SPDX-License-Identifier: GPL-3.0-or-later
"""SSH connection lifecycle."""

import logging
from typing import Optional

import paramiko

from ssh_tunnel_lib.handlers import open_ssh_socket
from ssh_tunnel_lib.tunnel_config import TunnelConfig

logger = logging.getLogger('ssh_tunnel_lib')


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
            try:
                pkey = paramiko.PKey.from_private_key_file(
                    config.key_filename, password=config.passphrase,
                )
            except Exception:
                logger.warning("Could not load key file %r", config.key_filename)

        client.connect(
            config.hostname, config.port, config.username,
            password=config.password,
            pkey=pkey,
            key_filename=None if pkey else config.key_filename,
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
