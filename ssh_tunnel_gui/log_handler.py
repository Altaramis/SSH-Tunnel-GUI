# Copyright (C) 2026  Altaramis
# SPDX-License-Identifier: GPL-3.0-or-later
"""Log handlers: buffering ring-buffer + live Qt text widget."""

import logging
from collections import deque
from typing import Deque

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
LOG_BUFFER_SIZE = 2000


class BufferingLogHandler(logging.Handler):
    """Always-active handler that keeps the last N formatted lines in memory."""

    def __init__(self, buffer: Deque[str]) -> None:
        super().__init__()
        self.buffer = buffer

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.buffer.append(self.format(record))
        except Exception:
            pass


def make_log_buffer() -> Deque[str]:
    return deque(maxlen=LOG_BUFFER_SIZE)


def attach_buffer(buffer: Deque[str]) -> BufferingLogHandler:
    """Attach a BufferingLogHandler to the two application loggers and return it."""
    handler = BufferingLogHandler(buffer)
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    for name in ('ssh_tunnel_lib', 'ssh_tunnel_table'):
        lg = logging.getLogger(name)
        lg.addHandler(handler)
        lg.setLevel(logging.DEBUG)
    return handler
