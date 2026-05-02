# Copyright (C) 2026  Altaramis
# SPDX-License-Identifier: GPL-3.0-or-later
"""High-level SSH tunnel manager."""

import logging
import threading
import uuid
from typing import Any, Callable, Dict, List, Optional

from ssh_tunnel_lib.connection import SSHConnection
from ssh_tunnel_lib.tunnel_config import TunnelConfig
from ssh_tunnel_lib.tunnels import BaseTunnel, create_tunnel

logger = logging.getLogger('ssh_tunnel_lib')


def _default_name(config: TunnelConfig) -> str:
    if config.forward_type == 'local':
        return f"{config.hostname}_L_{config.bind_port}->{config.remote_host}:{config.remote_port}"
    if config.forward_type == 'remote':
        return f"{config.hostname}_R_{config.bind_port}->{config.remote_host}:{config.remote_port}"
    return f"{config.hostname}_D_{config.bind_port}"


class TunnelInstance:
    """Associates a live SSH connection with its forwarding tunnel and original config."""

    def __init__(
        self,
        instance_id: str,
        connection: SSHConnection,
        tunnel: BaseTunnel,
        config: TunnelConfig,
    ) -> None:
        self.id         = instance_id
        self.name       = config.name or _default_name(config)
        self.connection = connection
        self.tunnel     = tunnel
        self.config     = config

    @property
    def is_active(self) -> bool:
        return self.connection.is_active

    def stop(self) -> None:
        self.tunnel.stop()
        self.connection.close()

    def info(self) -> Dict[str, Any]:
        return {
            'id':               self.id,
            'name':             self.name,
            'transport_active': self.is_active,
            'forward_type':     self.config.forward_type,
        }


class SSHManager:
    """Creates, tracks, and tears down SSH tunnels."""

    def __init__(self) -> None:
        self._instances: Dict[str, TunnelInstance] = {}
        self._lock = threading.RLock()

    def create_tunnel(
        self,
        config: TunnelConfig,
        instance_id: Optional[str] = None,
        host_key_callback: Optional[Callable[[str, str, str], str]] = None,
        changed_key_callback: Optional[Callable[[str, str, str, str], str]] = None,
    ) -> str:
        if instance_id is None:
            instance_id = str(uuid.uuid4())
        connection = SSHConnection.open(
            config,
            host_key_callback=host_key_callback,
            changed_key_callback=changed_key_callback,
        )
        tunnel = create_tunnel(connection, config)
        inst = TunnelInstance(instance_id, connection, tunnel, config)
        with self._lock:
            self._instances[instance_id] = inst
        logger.info("Tunnel created: %s (%s) id=%s", inst.name, config.forward_type, instance_id)
        return instance_id

    def close_instance(self, instance_id: str) -> None:
        with self._lock:
            inst = self._instances.pop(instance_id, None)
        if inst is None:
            raise KeyError(f"Instance not found: {instance_id!r}")
        inst.stop()
        logger.info("Tunnel closed: %s", instance_id)

    def list_instances(self) -> List[Dict[str, Any]]:
        with self._lock:
            snapshot = list(self._instances.values())
        return [inst.info() for inst in snapshot]

    def rename_instance(self, old_name: str, new_name: str) -> None:
        with self._lock:
            for inst in self._instances.values():
                if inst.name == old_name:
                    inst.name = new_name
                    return

    def stop_all(self) -> None:
        with self._lock:
            ids = list(self._instances.keys())
        for iid in ids:
            try:
                self.close_instance(iid)
            except Exception:
                pass
