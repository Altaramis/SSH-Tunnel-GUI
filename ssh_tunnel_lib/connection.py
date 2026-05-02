# Copyright (C) 2026  Altaramis
# SPDX-License-Identifier: GPL-3.0-or-later
"""SSH connection lifecycle."""

import base64
import hashlib
import logging
from typing import Callable, Optional

import paramiko

from ssh_tunnel_lib.handlers import open_ssh_socket
from ssh_tunnel_lib.tunnel_config import TunnelConfig

logger = logging.getLogger('ssh_tunnel_lib')

KNOWN_HOSTS_FILE = 'ssh_known_hosts'

_KEY_CLASSES = (
    paramiko.RSAKey,
    paramiko.ECDSAKey,
    paramiko.Ed25519Key,
)


def _fingerprint(key: paramiko.PKey) -> str:
    """Return the SHA256 fingerprint in OpenSSH format: 'SHA256:<base64>'."""
    digest = hashlib.sha256(key.asbytes()).digest()
    b64 = base64.b64encode(digest).decode().rstrip('=')
    return f'SHA256:{b64}'


class InteractiveHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """
    Called by paramiko when a host key is not in known_hosts.

    callback(hostname, key_type, fingerprint) -> 'accept_once' | 'accept_permanently' | 'reject'

    Without a callback, all unknown host keys are rejected (secure default).
    """

    def __init__(
        self,
        callback: Optional[Callable[[str, str, str], str]] = None,
        known_hosts_file: str = KNOWN_HOSTS_FILE,
    ) -> None:
        self._callback = callback
        self._known_hosts_file = known_hosts_file

    def missing_host_key(
        self,
        client: paramiko.SSHClient,
        hostname: str,
        key: paramiko.PKey,
    ) -> None:
        if self._callback is None:
            raise paramiko.ssh_exception.SSHException(
                f"Host key verification failed for {hostname!r}: host not in known_hosts."
            )
        decision = self._callback(hostname, key.get_name(), _fingerprint(key))
        if decision == 'accept_permanently':
            client.get_host_keys().add(hostname, key.get_name(), key)
            # HostKeys.save() directly — SSHClient.save_host_keys() re-reads the file first, failing if it doesn't exist yet.
            client.get_host_keys().save(self._known_hosts_file)
            logger.info('Host key accepted permanently: %s', hostname)
        elif decision == 'accept_once':
            client.get_host_keys().add(hostname, key.get_name(), key)
            logger.info('Host key accepted once: %s', hostname)
        else:
            raise paramiko.ssh_exception.SSHException(
                f"Host key rejected by user for {hostname!r}."
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
    def open(
        cls,
        config: TunnelConfig,
        timeout: float = 10.0,
        host_key_callback: Optional[Callable[[str, str, str], str]] = None,
        changed_key_callback: Optional[Callable[[str, str, str, str], str]] = None,
        known_hosts_file: str = KNOWN_HOSTS_FILE,
    ) -> 'SSHConnection':
        """Establish an SSH connection as described by *config*."""
        pkey: Optional[paramiko.PKey] = None
        if config.key_filename:
            pkey = _load_private_key(config.key_filename, config.passphrase)

        client: Optional[paramiko.SSHClient] = None
        for _attempt in range(2):
            sock = open_ssh_socket(config.hostname, config.port, config.proxy, timeout)
            client = paramiko.SSHClient()
            try:
                client.load_host_keys(known_hosts_file)
            except FileNotFoundError:
                pass
            client.set_missing_host_key_policy(
                InteractiveHostKeyPolicy(host_key_callback, known_hosts_file)
            )
            try:
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
                break  # connected successfully
            except paramiko.BadHostKeyException as exc:
                client.close()
                if _attempt > 0 or changed_key_callback is None:
                    raise
                old_fp = _fingerprint(exc.expected_key)
                new_fp = _fingerprint(exc.key)
                decision = changed_key_callback(exc.hostname, exc.key.get_name(), old_fp, new_fp)
                if decision != 'update':
                    raise paramiko.ssh_exception.SSHException(
                        f"Host key update rejected by user for {exc.hostname!r}."
                    ) from exc
                # BadHostKeyException.hostname is the plain hostname; known_hosts uses "[hostname]:port" for non-standard ports.
                hosts_key = (
                    f"[{exc.hostname}]:{config.port}"
                    if config.port != 22
                    else exc.hostname
                )
                kh = paramiko.HostKeys()
                try:
                    kh.load(known_hosts_file)
                except FileNotFoundError:
                    pass
                kh.pop(hosts_key, None)
                kh.add(hosts_key, exc.key.get_name(), exc.key)
                kh.save(known_hosts_file)
                logger.info('Host key updated for %s, retrying connection', exc.hostname)

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
