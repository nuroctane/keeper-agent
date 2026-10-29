"""Serialize workspace edits across administrator processes and threads.

JSON remains the workspace format. Each writer holds the same OS file lock for
the entire read/modify/replace operation; process exit releases the lock.
"""
from __future__ import annotations

import contextlib
import os
import threading
import time

from .security import Denied

_guard = threading.Lock()
_locks = {}
_held = threading.local()


@contextlib.contextmanager
def transaction(state):
    key = str(state.resolve())
    with _guard:
        lock = _locks.setdefault(key, threading.RLock())
    if not lock.acquire(timeout=10):
        raise Denied("Workspace is busy. Try again shortly.", "workspace_busy")
    stream = None
    held = getattr(_held, "states", set())
    nested = key in held
    try:
        if not nested:
            fd = os.open(state / ".workspace.lock", os.O_RDWR | os.O_CREAT, 0o600)
            stream = os.fdopen(fd, "r+b", buffering=0)
            deadline = time.monotonic() + 10
            while True:
                try:
                    stream.seek(0)
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except (BlockingIOError, PermissionError):
                    if time.monotonic() >= deadline:
                        raise Denied("Workspace is busy. Try again shortly.", "workspace_busy") from None
                    time.sleep(0.02)
            _held.states = held | {key}
        yield
    finally:
        if stream is not None:
            # Closing the descriptor releases the OS lock, including on errors.
            stream.close()
        if not nested:
            _held.states = held
        lock.release()
