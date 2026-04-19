# Copyright (C) 2026  Altaramis
# SPDX-License-Identifier: GPL-3.0-or-later
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class TunnelConfig:
    forward_type:       str                    # 'local' | 'dynamic' | 'remote'
    hostname:           str
    port:               int
    username:           str
    bind_addr:          str                    = '127.0.0.1'
    bind_port:          int                    = 2226
    remote_host:        str                    = ''
    remote_port:        int                    = 0
    password:           Optional[str]          = None
    key_filename:       Optional[str]          = None
    passphrase:         Optional[str]          = None
    allow_agent:        bool                   = True
    look_for_keys:      bool                   = True
    proxy:              Optional[Dict[str, Any]] = None
    keepalive_interval: int                    = 0
    name:               Optional[str]          = None
