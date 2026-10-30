"""Narrow, one-request stdio bridge for the native administrator UI.

No listener, vault reads, master passwords, or capability tokens cross this bridge.
Run results follow the existing broker's policy and best-effort redaction rules.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import socket
import ssl
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from .cli import add_client, call_client, initialize, replace_private, revoke_client
from .audit import files as audit_files
from .policy import NAME, validate
from .security import Denied, read_json
from .state import transaction

REGIONS = {"US": "keepersecurity.com", "EU": "keepersecurity.eu", "AU": "keepersecurity.com.au",
           "CA": "keepersecurity.ca", "JP": "keepersecurity.jp", "US GOV": "govcloud.keepersecurity.us"}
# Name fragments that mark a header or environment variable as carrying a credential.
CREDENTIAL_WORDS = ("auth", "key", "token", "cookie", "secret", "pass", "pwd", "session",
                    "credential", "signature", "bearer")


def policy_digest(policy):
    return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def online(state):
    try:
        port = read_json(state / "server.json")["port"]
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=str(state / "server.crt"))
        with socket.create_connection(("127.0.0.1", port), timeout=0.35) as sock:
            with ctx.wrap_socket(sock, server_hostname="127.0.0.1"):
                return True
    except (OSError, ValueError, KeyError):
        return False


def audit_tail(state):
    entries = []
    budget = 262144
    for path in reversed(audit_files(state)):
        if budget <= 0 or len(entries) >= 200:
            break
        try:
            with path.open("rb") as stream:
                stream.seek(0, 2)
                size = stream.tell()
                start = max(0, size - budget)
                stream.seek(start)
                chunk = stream.read(budget)
        except FileNotFoundError:
            # Rotation can rename the current file between listing and opening.
            continue
        budget -= len(chunk)
        lines = chunk.splitlines()
        if start:
            lines = lines[1:]  # discard a possibly partial first line
        for line in reversed(lines):
            try:
                raw = json.loads(line)
                entry = {key: str(raw.get(key, ""))[:160] for key in ("id", "time", "client", "action", "status")}
                if entry["status"] in {"started", "completed", "failed"}:
                    entries.append(entry)
                    if len(entries) >= 200:
                        break
            except (ValueError, AttributeError):
                continue
    return entries


def snapshot(state):
    base = {"initialized": False, "online": False, "email": "", "region": "US", "port": 19463,
            "actions": [], "clients": [], "events": [], "pendingRestart": False, "statePath": str(state)}
    if not (state / "keeper.json").exists():
        return base
    policy = validate(read_json(state / "policy.json"))
    clients = read_json(state / "clients.json")
    account = read_json(state / "keeper.json")
    base.update(initialized=True, online=online(state), email=account.get("user", ""),
                region=next((k for k, v in REGIONS.items() if v == account.get("server")), "Custom"),
                port=read_json(state / "server.json")["port"])
    for name, action in sorted(policy["actions"].items()):
        kind = action["kind"]
        destination = (urlsplit(action["url"]).hostname if kind == "http" else
                       Path(action["argv"][0]).name if kind == "command" else
                       ", ".join(urlsplit(url).hostname or "" for url in action["origins"]))
        base["actions"].append({"name": name, "kind": kind, "description": action.get("description", ""),
                                "destination": destination, "secrets": len(action.get("secrets", {})),
                                "timeout": action.get("timeout", 60),
                                "grants": sum(name in x["actions"] for x in clients.values()
                                              if not x.get("desktopTemporary"))})
    base["clients"] = [{"name": name, "actions": data["actions"], "expiresAt": data.get("expiresAt"),
                        "expired": data.get("expiresAt", float("inf")) <= time.time()}
                       for name, data in sorted(clients.items())
                       if not data.get("desktopTemporary")]
    base["events"] = audit_tail(state)
    status = state / "broker-status.json"
    if base["online"] and status.exists():
        base["pendingRestart"] = read_json(status).get("policyDigest") != policy_digest(policy)
    elif base["online"]:
        # Older broker builds do not advertise their policy revision.
        base["pendingRestart"] = True
    return base


def validate_templates(action):
    """The UI's policy editor must not introduce literal credential headers/env."""
    for key, value in action.get("headers", {}).items():
        if any(word in key.lower() for word in CREDENTIAL_WORDS) and "{{" not in value:
            raise Denied("Use a Keeper reference for credential headers, such as Bearer {{token}}")
    for key, value in action.get("env", {}).items():
        if any(word in key.lower() for word in CREDENTIAL_WORDS) and "{{" not in value:
            raise Denied("Use Keeper references for credential environment variables")


def dispatch(request):
    # The lock covers each whole edit, including reads, across CLI/native/web.
    # Never hold it while executing an action or waiting for Keeper.
    if isinstance(request, dict) and request.get("operation") in {
            "save_action", "delete_action", "create_client", "revoke_client"}:
        path = request.get("state")
        if isinstance(path, str):
            folder = Path(path).expanduser()
            if folder.is_absolute() and folder.is_dir():
                with transaction(folder.resolve()):
                    return _dispatch(request)
    return _dispatch(request)


def _dispatch(request):
    if not isinstance(request, dict) or not isinstance(request.get("state"), str):
        raise Denied("Select a broker folder first")
    state = Path(request["state"]).expanduser()
    if not state.is_absolute():
        raise Denied("Broker folder must be an absolute path")
    state = state.resolve()
    op = request.get("operation")
    if op == "snapshot":
        return snapshot(state)
    if op == "initialize":
        email = request.get("email", "").strip()
        region = request.get("region", "US")
        if "@" not in email or len(email) > 254 or region not in REGIONS:
            raise Denied("Enter a valid email and Keeper region")
        with contextlib.redirect_stdout(io.StringIO()):
            initialize(state, email, 19463)
        config = read_json(state / "keeper.json")
        config["server"] = REGIONS[region]
        replace_private(state / "keeper.json", config)
        return snapshot(state)
    if not (state / "keeper.json").is_file():
        raise Denied("Set up or choose an existing broker folder first")
    policy = validate(read_json(state / "policy.json"))
    name = request.get("name", "")
    if op in {"get_action", "save_action", "delete_action", "create_client", "revoke_client", "run"}:
        if not isinstance(name, str) or not NAME.fullmatch(name) or name.startswith("desktop-run-"):
            raise Denied("Use a name containing letters, numbers, dots, underscores, or hyphens")
    if op == "get_action":
        if name not in policy["actions"]:
            raise Denied("Action no longer exists")
        return policy["actions"][name]
    if op == "save_action":
        action = request.get("action")
        if name in policy["actions"] and request.get("replace") is not True:
            raise Denied("An action with that name already exists")
        policy["actions"][name] = action
        validate(policy)
        validate_templates(action)
        replace_private(state / "policy.json", policy)
        return snapshot(state)
    if op == "delete_action":
        clients = read_json(state / "clients.json")
        if any(name in client["actions"] for client in clients.values()):
            raise Denied("Revoke agent access to this action before deleting it")
        if name not in policy["actions"]:
            raise Denied("Action no longer exists")
        del policy["actions"][name]
        replace_private(state / "policy.json", policy)
        return snapshot(state)
    if op == "create_client":
        grants = request.get("actions")
        if not isinstance(grants, list) or not all(isinstance(x, str) for x in grants):
            raise Denied("Select permitted actions")
        filename = state / f"{name}-client.json"
        with contextlib.redirect_stdout(io.StringIO()):
            add_client(state, name, grants, filename, expires_in=request.get("expiresIn", 7 * 86400))
        return {"path": str(filename), "snapshot": snapshot(state)}
    if op == "revoke_client":
        revoke_client(state, name)
        return snapshot(state)
    if op == "run":
        if name not in policy["actions"]:
            raise Denied("Action no longer exists")
        current = snapshot(state)
        if not current["online"]:
            raise Denied("The broker is not connected. Connect Keeper first.", "broker_offline")
        # A current broker applies policy edits within about a second; give it
        # that long before concluding it is an older build that needs a restart.
        deadline = time.monotonic() + 3
        while current["pendingRestart"] and time.monotonic() < deadline:
            time.sleep(0.25)
            current = snapshot(state)
        if current["pendingRestart"]:
            raise Denied("The broker has not applied the latest policy. Restart it before running.")
        client_name = "desktop-run-" + uuid.uuid4().hex
        filename = state / f"{client_name}-client.json"
        result = None
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                add_client(state, client_name, [name], filename, expires_in=360, temporary=True)
            result = call_client(filename, {"operation": "run", "action": name})
        finally:
            try:
                revoke_client(state, client_name, missing_ok=True)
                filename.unlink(missing_ok=True)
            except Exception:
                if result is not None:
                    result["warning"] = "The action completed, but temporary access cleanup failed. Access expires automatically."
        return result
    raise Denied("Unsupported desktop operation")


def handle_request(raw):
    try:
        if len(raw) > 1048576:
            raise Denied("Request is too large")
        result = dispatch(json.loads(raw))
        return {"ok": True, "data": result}
    except Denied as error:
        return {"ok": False, **error.payload()}
    except Exception:
        return {"ok": False, "error": "Could not complete the request. Check broker configuration and permissions."}


def stdio_worker():
    # The parent sends one bounded JSON request per line. EOF also makes the
    # helper exit when its owning desktop process goes away.
    while True:
        raw = sys.stdin.buffer.readline(1048578)
        if not raw:
            return 0
        if len(raw) > 1048577 or (len(raw) == 1048577 and not raw.endswith(b"\n")):
            while raw and not raw.endswith(b"\n"):
                raw = sys.stdin.buffer.readline(65536)
            payload = {"ok": False, "error": "Request is too large"}
        else:
            payload = handle_request(raw.rstrip(b"\n"))
        encoded = json.dumps(payload).encode("utf-8")
        if len(encoded) > 1048576:
            payload = {"ok": False, "error": "Response was too large; an action may have run.",
                       "code": "outcome_unknown", "hint": "Check the destination before repeating an action."}
            encoded = json.dumps(payload).encode("utf-8")
        sys.stdout.buffer.write(encoded + b"\n")
        sys.stdout.buffer.flush()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--stdio-worker":
        return stdio_worker()
    if len(sys.argv) > 1 and sys.argv[1] == "web-worker":
        from .web_worker import main as worker_main
        return worker_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "web":
        from .web import main as web_main
        return web_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "install-browser":
        from playwright.__main__ import main as playwright_main
        sys.argv = ["playwright", "install", "chromium"]
        return playwright_main()
    if len(sys.argv) > 1 and sys.argv[1] in {
            "serve", "init", "validate", "client-add", "client-revoke", "doctor", "audit-verify",
            "list", "run", "status", "--help", "-h"}:
        from .cli import main as cli_main
        return cli_main(sys.argv[1:])
    payload = handle_request(sys.stdin.buffer.read(1048577))
    sys.stdout.write(json.dumps(payload))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
