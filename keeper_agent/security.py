from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import quote, quote_plus, urlsplit


class Denied(Exception):
    """A deliberately non-sensitive error suitable for the agent interface."""


def read_json(path):
    with open(path, encoding="utf-8-sig") as stream:
        return json.load(stream)


def write_private(path: Path, value):
    # Windows state ACLs are applied by init before anything sensitive is written.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def origin(url):
    p = urlsplit(url)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.fragment:
        raise Denied("Only HTTPS URLs without userinfo or fragments are permitted")
    host = p.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}:{p.port or 443}"


def scrub(value, secrets):
    variants = set()
    for secret in secrets:
        if not secret:
            continue
        variants.update((secret, quote(secret, safe=""), quote_plus(secret),
                         base64.b64encode(secret.encode()).decode(),
                         json.dumps(secret, ensure_ascii=True)[1:-1]))
    def clean(item):
        if isinstance(item, str):
            for secret in sorted(variants, key=len, reverse=True):
                item = item.replace(secret, "[REDACTED]")
            return item
        if isinstance(item, list):
            return [clean(x) for x in item]
        if isinstance(item, dict):
            return {clean(k): clean(v) for k, v in item.items()}
        return item
    return clean(value)
