# Copyright (C) 2026  Altaramis
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tunnel types: local (-L), dynamic SOCKS5 (-D), remote (-R)."""

import logging
import socket
import threading
from abc import ABC, abstractmethod
from typing import Optional

from ssh_tunnel_lib.connection import SSHConnection
from ssh_tunnel_lib.handlers import (
    _ForwardTCPHandler,
    _RemoteChannelAcceptor,
    _Socks5Handler,
    _TCPServer,
)
from ssh_tunnel_lib.tunnel_config import TunnelConfig

logger = logging.getLogger('ssh_tunnel_lib')


class BaseTunnel(ABC):
    """Common interface for all tunnel types."""

    @abstractmethod
    def start(self) -> None:
        """Start relaying traffic."""

    @abstractmethod
    def stop(self) -> None:
        """Stop relaying and release resources."""

    @property
    @abstractmethod
    def is_active(self) -> bool:
        """True while the tunnel is actively serving connections."""


class LocalTunnel(BaseTunnel):
    """Listens on bind_addr:bind_port and forwards each connection to remote_host:remote_port over SSH."""

    def __init__(self, connection: SSHConnection, config: TunnelConfig) -> None:
        self._connection = connection
        self._config     = config
        self._server: Optional[_TCPServer] = None

    def start(self) -> None:
        addrinfo = socket.getaddrinfo(
            self._config.bind_addr, self._config.bind_port, 0, socket.SOCK_STREAM,
        )
        server = _TCPServer(
            (self._config.bind_addr, self._config.bind_port), _ForwardTCPHandler,
        )
        server.address_family       = addrinfo[0][0]
        server.transport            = self._connection.transport   # type: ignore[attr-defined]
        server.remote_host          = self._config.remote_host     # type: ignore[attr-defined]
        server.remote_port          = self._config.remote_port     # type: ignore[attr-defined]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self._server = server
        logger.debug(
            "Local forward %s:%d → %s:%d",
            self._config.bind_addr, self._config.bind_port,
            self._config.remote_host, self._config.remote_port,
        )

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None

    @property
    def is_active(self) -> bool:
        return self._server is not None


class DynamicTunnel(BaseTunnel):
    """SOCKS5 proxy on bind_addr:bind_port that tunnels all connections over SSH."""

    def __init__(self, connection: SSHConnection, config: TunnelConfig) -> None:
        self._connection = connection
        self._config     = config
        self._server: Optional[_TCPServer] = None

    def start(self) -> None:
        addrinfo = socket.getaddrinfo(
            self._config.bind_addr, self._config.bind_port, 0, socket.SOCK_STREAM,
        )
        server = _TCPServer(
            (self._config.bind_addr, self._config.bind_port), _Socks5Handler,
        )
        server.address_family = addrinfo[0][0]
        server.transport      = self._connection.transport  # type: ignore[attr-defined]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self._server = server
        logger.debug(
            "Dynamic SOCKS5 proxy on %s:%d",
            self._config.bind_addr, self._config.bind_port,
        )

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None

    @property
    def is_active(self) -> bool:
        return self._server is not None


class RemoteTunnel(BaseTunnel):
    """Asks the SSH server to listen on bind_port and relay inbound connections to remote_host:remote_port."""

    def __init__(self, connection: SSHConnection, config: TunnelConfig) -> None:
        self._connection = connection
        self._config     = config
        self._acceptor: Optional[_RemoteChannelAcceptor] = None

    def start(self) -> None:
        transport = self._connection.transport
        if transport is None:
            raise RuntimeError("SSH transport is not available")
        transport.request_port_forward(self._config.bind_addr or '', self._config.bind_port)
        acceptor = _RemoteChannelAcceptor(
            transport, self._config.remote_host, self._config.remote_port,
        )
        threading.Thread(target=acceptor.serve, daemon=True).start()
        self._acceptor = acceptor
        logger.debug(
            "Remote forward: server :%d → local %s:%d",
            self._config.bind_port,
            self._config.remote_host, self._config.remote_port,
        )

    def stop(self) -> None:
        if self._acceptor is not None:
            try:
                self._acceptor.stop()
            except Exception:
                pass
            self._acceptor = None

    @property
    def is_active(self) -> bool:
        return self._acceptor is not None and self._acceptor.is_running


# ------------------------------------------------------------------
# Factory
# ------------------------------------------------------------------

_TUNNEL_CLASSES = {
    'local':   LocalTunnel,
    'dynamic': DynamicTunnel,
    'remote':  RemoteTunnel,
}


def create_tunnel(connection: SSHConnection, config: TunnelConfig) -> BaseTunnel:
    """Instantiate and start the appropriate tunnel type for *config*."""
    cls = _TUNNEL_CLASSES.get(config.forward_type)
    if cls is None:
        raise ValueError(f"Unknown forward_type: {config.forward_type!r}")
    tunnel = cls(connection, config)
    tunnel.start()
    return tunnel
