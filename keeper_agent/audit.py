"""Append-only audit log: hash-chained entries with size-based rotation.

Each entry records the SHA-256 of the previous line, so editing, inserting or
removing an earlier entry breaks the chain, including across rotated files.
This detects tampering by anyone who cannot rewrite the whole log. The broker
account itself can, so the chain is evidence, not a guarantee.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
from datetime import datetime, timedelta, timezone

CURRENT = "audit.jsonl"
LIMIT = 8 * 1024 * 1024
GENESIS = "0" * 64


def line_hash(raw):
    return hashlib.sha256(raw.rstrip(b"\r\n")).hexdigest()


def files(state):
    # Rotation names increase even when the system clock moves backwards.
    rotated = sorted(state.glob("audit-*.jsonl"))
    current = state / CURRENT
    return rotated + ([current] if current.exists() else [])


def last_line(path):
    with path.open("rb") as stream:
        stream.seek(0, 2)
        size = stream.tell()
        stream.seek(max(0, size - 65536))
        lines = [line for line in stream.read().splitlines() if line.strip()]
    return lines[-1] if lines else None


def last_hash(state):
    for path in reversed(files(state)):
        line = last_line(path)
        if line is not None:
            return line_hash(line)
    return GENESIS


class AuditLog:
    def __init__(self, state, limit=LIMIT):
        self.state = state
        self.limit = limit
        self.lock = threading.Lock()
        self.prev = None

    def append(self, entry):
        with self.lock:
            path = self.state / CURRENT
            if self.prev is None:
                self.prev = last_hash(self.state)
            if path.exists() and path.stat().st_size >= self.limit:
                stamp_format = "%Y%m%dT%H%M%S%fZ"
                stamp = datetime.now(timezone.utc).strftime(stamp_format)
                latest = max(self.state.glob("audit-*.jsonl"), default=None)
                if latest is not None:
                    previous = latest.name.split("-")[1]
                    if stamp <= previous:
                        stamp = (datetime.strptime(previous, stamp_format) + timedelta(microseconds=1)).strftime(stamp_format)
                try:
                    path.replace(self.state / f"audit-{stamp}-{secrets.token_hex(2)}.jsonl")
                except PermissionError:
                    # Windows refuses to rename a file another reader has open,
                    # such as the admin's activity view. Rotate on a later write
                    # rather than failing the action; the chain is unaffected.
                    pass
            raw = json.dumps({**entry, "prev": self.prev}).encode()
            with path.open("ab") as stream:
                stream.write(raw + b"\n")
                stream.flush()
            self.prev = line_hash(raw)


def verify(state):
    """Return (entries checked, None) or (entries checked, first problem found)."""
    expected = GENESIS
    chained = False
    count = 0
    for path in files(state):
        with path.open("rb") as stream:
            for number, raw in enumerate(stream, 1):
                if not raw.strip():
                    continue
                where = f"{path.name} line {number}"
                try:
                    entry = json.loads(raw)
                except ValueError:
                    return count, f"{where} is not valid JSON"
                if not isinstance(entry, dict):
                    return count, f"{where} is not an audit entry"
                if "prev" not in entry:
                    # Entries written before hash chaining began. They may only
                    # precede the chain, never appear inside it.
                    if chained:
                        return count, f"{where} is missing its chain link"
                elif entry["prev"] != expected:
                    return count, f"{where} does not follow the previous entry"
                else:
                    chained = True
                expected = line_hash(raw)
                count += 1
    return count, None
