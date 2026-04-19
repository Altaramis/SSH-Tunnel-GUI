# Copyright (C) 2026  Altaramis
# SPDX-License-Identifier: GPL-3.0-or-later
"""Low-level TCP and SOCKS5 relay handlers."""

import logging
import select
import socket
import socketserver
import threading
from typing import Any, Dict, Optional

import paramiko
import socks

logger = logging.getLogger('ssh_tunnel_lib')


# ------------------------------------------------------------------
# Socket helpers
# ------------------------------------------------------------------

def open_ssh_socket(
    host: str,
    port: int,
    proxy: Optional[Dict[str, Any]] = None,
    timeout: float = 10.0,
) -> socket.socket:
    """Return a connected socket to (host, port), optionally via a proxy."""
    if proxy is None:
        return socket.create_connection((host, port), timeout=timeout)

    ptype = proxy.get('proxy_type', 'socks5').lower()
    stype_map = {
        'socks5': socks.PROXY_TYPE_SOCKS5,
        'socks4': socks.PROXY_TYPE_SOCKS4,
        'http':   socks.PROXY_TYPE_HTTP,
    }
    stype = stype_map.get(ptype)
    if stype is None:
        raise ValueError(f"Unsupported proxy_type: {ptype!r}")

    s = socks.socksocket()
    s.set_proxy(
        stype,
        proxy.get('addr', 'localhost'),
        proxy.get('port', 1080),
        rdns=proxy.get('rdns', True),
        username=proxy.get('username'),
        password=proxy.get('password'),
    )
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def _relay(src: Any, dst: Any) -> None:
    """Bidirectional relay between two socket-like objects until one side closes."""
    peers = [src, dst]
    try:
        while True:
            readable, _, exceptional = select.select(peers, [], peers, 1.0)
            if exceptional:
                break
            if src in readable:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
            if dst in readable:
                data = dst.recv(4096)
                if not data:
                    break
                src.sendall(data)
    except Exception:
        logger.exception("Relay error")
    finally:
        for s in peers:
            try:
                s.close()
            except Exception:
                pass


# ------------------------------------------------------------------
# TCP server base
# ------------------------------------------------------------------

class _TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ------------------------------------------------------------------
# Local-forward handler
# ------------------------------------------------------------------

class _ForwardTCPHandler(socketserver.BaseRequestHandler):
    """Accepts one local connection and forwards it through the SSH transport."""

    def setup(self) -> None:
        srv = self.server
        self._transport: paramiko.Transport = srv.transport    # type: ignore[attr-defined]
        self._remote_host: str              = srv.remote_host  # type: ignore[attr-defined]
        self._remote_port: int              = srv.remote_port  # type: ignore[attr-defined]

    def handle(self) -> None:
        try:
            chan = self._transport.open_channel(
                'direct-tcpip',
                (self._remote_host, self._remote_port),
                self.request.getpeername(),
                timeout=10.0,
            )
        except Exception:
            logger.exception("Failed to open SSH channel")
            return
        if chan is None:
            logger.warning("open_channel returned None")
            return
        _relay(self.request, chan)


# ------------------------------------------------------------------
# SOCKS5 handler
# ------------------------------------------------------------------

def _socks5_reply(conn: socket.socket, rep: int) -> None:
    resp = b'\x05' + bytes([rep]) + b'\x00\x01' + socket.inet_aton('0.0.0.0') + b'\x00\x00'
    try:
        conn.sendall(resp)
    except Exception:
        pass


class _Socks5Handler(socketserver.StreamRequestHandler):
    """Minimal SOCKS5 (no-auth, CONNECT only) proxy that tunnels over SSH."""

    def setup(self) -> None:
        super().setup()
        self._transport: paramiko.Transport = self.server.transport  # type: ignore[attr-defined]

    def handle(self) -> None:
        conn = self.connection
        try:
            data = conn.recv(262)
            if not data or data[0] != 0x05:
                return
            conn.sendall(b'\x05\x00')  # no-auth accepted

            header = conn.recv(4)
            if len(header) < 4:
                return
            _ver, cmd, _rsv, atyp = header

            if atyp == 0x01:
                addr = socket.inet_ntoa(conn.recv(4))
            elif atyp == 0x03:
                alen = conn.recv(1)[0]
                addr = conn.recv(alen).decode()
            elif atyp == 0x04:
                addr = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
            else:
                return

            port = int.from_bytes(conn.recv(2), 'big')

            if cmd != 0x01:
                _socks5_reply(conn, 0x07)
                return

            chan = self._transport.open_channel(
                'direct-tcpip', (addr, port),
                self.request.getpeername(), timeout=10.0,
            )
            if chan is None:
                _socks5_reply(conn, 0x05)
                return

            _socks5_reply(conn, 0x00)
            _relay(conn, chan)
        except Exception:
            logger.exception("SOCKS5 handler error")


# ------------------------------------------------------------------
# Remote-forward acceptor
# ------------------------------------------------------------------

class _RemoteChannelAcceptor:
    """Accepts reverse-tunnel channels opened by the SSH server and relays locally."""

    def __init__(
        self,
        transport: paramiko.Transport,
        target_host: str,
        target_port: int,
    ) -> None:
        self._transport  = transport
        self._target_host = target_host
        self._target_port = target_port
        self._stop = threading.Event()

    def serve(self) -> None:
        while not self._stop.is_set():
            try:
                chan = self._transport.accept(timeout=1.0)
            except Exception:
                break
            if chan is None:
                continue
            threading.Thread(
                target=self._handle_channel, args=(chan,), daemon=True,
            ).start()

    def _handle_channel(self, chan: paramiko.Channel) -> None:
        try:
            sock = socket.create_connection(
                (self._target_host, self._target_port), timeout=10.0,
            )
        except Exception:
            logger.exception(
                "Remote relay: cannot reach %s:%d",
                self._target_host, self._target_port,
            )
            chan.close()
            return
        _relay(chan, sock)

    def stop(self) -> None:
        self._stop.set()

    @property
    def is_running(self) -> bool:
        return not self._stop.is_set()
