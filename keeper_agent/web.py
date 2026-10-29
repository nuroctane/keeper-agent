"""Authenticated, same-origin administrator web app; separate from the agent API."""
from __future__ import annotations

import argparse
from collections import deque
import hashlib
import hmac
import ipaddress
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit, unquote

from .cli import protect_directory
from .desktop import dispatch, online
from .policy import NAME
from .security import Denied, read_json

OPERATIONS = {"snapshot", "initialize", "get_action", "save_action", "delete_action", "create_client", "revoke_client", "run"}
COOKIE = "keeper_admin"


class Worker:
    def __init__(self):
        self.lock = threading.RLock()
        self.process = None
        self.owner = None
        self.status = {"state": "idle"}
        self.deadline = None

    def start(self, state, owner, install=False):
        with self.lock:
            if self.process and self.process.poll() is None:
                raise Denied("This task is already running")
            if getattr(sys, "frozen", False):
                argv = [sys.executable, "web-worker"]
            else:
                argv = [sys.executable, "-m", "keeper_agent.web_worker"]
            argv += ["--install-browser"] if install else ["--state", str(state)]
            self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, encoding="utf-8", bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            self.owner = owner
            self.status = {"state": "installing" if install else "connecting"}
            proc = self.process
            self.deadline = threading.Timer(600, lambda: self.stop(expected=proc, expired=True))
            self.deadline.daemon = True
            self.deadline.start()
            threading.Thread(target=self._read, args=(proc,), daemon=True).start()
            return self.get(owner)

    def _read(self, proc):
        try:
            while line := proc.stdout.readline(65537):
                if len(line) > 65536:
                    break
                message = json.loads(line)
                if message.get("state") not in {"challenge", "connecting", "connected", "completed", "failed"}:
                    break
                with self.lock:
                    if self.process is not proc:
                        return
                    self.status = message
                    if message["state"] in {"connected", "completed", "failed"} and self.deadline:
                        self.deadline.cancel()
            proc.wait(timeout=5)
        except Exception:
            self.stop(expected=proc, expired=True)
        finally:
            with self.lock:
                if self.process is proc and self.status["state"] not in {"completed", "failed", "idle"}:
                    self.status = {"state": "failed", "error": "The broker process stopped. Connect again."}

    def get(self, owner):
        with self.lock:
            if self.status["state"] == "challenge" and owner != self.owner:
                return {"state": "other-session"}
            return dict(self.status)

    def answer(self, owner, payload):
        with self.lock:
            challenge = self.status.get("challenge", {})
            if owner != self.owner or self.status["state"] != "challenge" or payload.get("id") != challenge.get("id"):
                raise Denied("Login challenge expired or belongs to another session")
            allowed = {option["id"] for option in challenge.get("options", [])} | {"cancel"}
            if payload.get("action") not in allowed or not isinstance(payload.get("value", ""), str) or len(payload.get("value", "")) > 4096:
                raise Denied("Invalid login response")
            self.process.stdin.write(json.dumps({key: payload[key] for key in ("id", "action", "value") if key in payload}) + "\n")
            self.process.stdin.flush()
            self.status = {"state": "connecting"}
            return self.get(owner)

    def stop(self, expected=None, expired=False):
        with self.lock:
            if expected is not None and expected is not self.process:
                return
            proc = self.process
            self.process = None
            if self.deadline:
                self.deadline.cancel()
            self.status = {"state": "failed", "error": "Task timed out. Start again."} if expired else {"state": "idle"}
        if proc:
            import psutil
            # Closing stdin asks the worker to stop on its own, which logs out of
            # Keeper and removes its status file. Force it only if it lingers.
            try:
                if proc.stdin:
                    proc.stdin.close()
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
            try:
                if proc.poll() is None:
                    parent = psutil.Process(proc.pid)
                    children = parent.children(recursive=True)
                    for child in children:
                        child.terminate()
                    parent.terminate()
                    _, living = psutil.wait_procs([*children, parent], timeout=3)
                    for child in living:
                        child.kill()
            except psutil.NoSuchProcess:
                pass
            if proc.stdout:
                try:
                    proc.stdout.close()
                except OSError:
                    pass


class WebAdmin:
    def __init__(self, state, assets, origin, access_key):
        self.state = Path(state).resolve()
        self.assets = Path(assets).resolve()
        self.origin = origin
        self.authority = urlsplit(origin).netloc
        self.secure = origin.startswith("https://")
        self.key_hash = hashlib.sha256(access_key.encode()).digest()
        self.sessions = {}
        self.attempts = deque()
        self.auth_lock = threading.Lock()
        self.gate = threading.Lock()
        self.connection = Worker()
        self.browser = Worker()

    def login(self, key):
        now = time.monotonic()
        with self.auth_lock:
            while self.attempts and self.attempts[0] < now - 60:
                self.attempts.popleft()
            # The random 256-bit key cannot be guessed, so the throttle only bounds
            # wrong attempts. The correct key is checked first so that nobody can
            # lock the administrator out by submitting wrong keys.
            if not isinstance(key, str) or len(key) > 256 or not hmac.compare_digest(hashlib.sha256(key.encode()).digest(), self.key_hash):
                if len(self.attempts) >= 10:
                    raise Denied("Too many sign-in attempts. Wait one minute.")
                self.attempts.append(now)
                raise Denied("Invalid administrator access key")
            self.sessions = {k: v for k, v in self.sessions.items() if now - v["seen"] < 1800 and now - v["created"] < 28800}
            if len(self.sessions) >= 16:
                self.sessions.pop(next(iter(self.sessions)))
            session = secrets.token_urlsafe(32)
            csrf = secrets.token_urlsafe(32)
            self.sessions[session] = {"csrf": csrf, "created": now, "seen": now}
            return session, csrf

    def authenticate(self, headers, mutation=False):
        cookie = SimpleCookie()
        cookie.load(headers.get("Cookie", ""))
        morsel = cookie.get(COOKIE)
        session = morsel.value if morsel else ""
        now = time.monotonic()
        with self.auth_lock:
            value = self.sessions.get(session)
            if not value or now - value["seen"] >= 1800 or now - value["created"] >= 28800:
                self.sessions.pop(session, None)
                raise PermissionError("Sign in to the administrator workspace")
            if mutation and not hmac.compare_digest(headers.get("X-CSRF-Token", ""), value["csrf"]):
                raise Denied("Invalid request protection token")
            value["seen"] = now
            return session, value["csrf"]

    def logout(self, session):
        with self.auth_lock:
            self.sessions.pop(session, None)
        if self.connection.owner == session and self.connection.get(session)["state"] in {"challenge", "connecting"}:
            self.connection.stop()

    def operation(self, payload, session):
        op = payload.get("operation")
        if op == "connection_status":
            return self.connection.get(session)
        if op == "browser_status":
            return self.browser.get(session)
        if op == "login_answer":
            return self.connection.answer(session, payload)
        if not self.gate.acquire(blocking=False):
            raise Denied("Another administrator operation is running. Try again when it finishes.")
        try:
            if op == "connect":
                if not (self.state / "keeper.json").is_file():
                    raise Denied("Create or select a workspace first")
                if online(self.state):
                    raise Denied("A broker is already connected")
                return self.connection.start(self.state, session)
            if op == "disconnect":
                if not self.connection.process and online(self.state):
                    raise Denied("This broker was opened outside the web app. Stop it in its private terminal.")
                self.connection.stop()
                return {"state": "idle"}
            if op == "install_browser":
                return self.browser.start(self.state, session, install=True)
            if op == "select_state":
                if self.connection.process and self.connection.process.poll() is None:
                    raise Denied("Disconnect this workspace before switching folders")
                path = Path(payload.get("path", ""))
                if not path.is_absolute() or not (path / "keeper.json").is_file():
                    raise Denied("Enter an absolute broker-host folder containing keeper.json")
                self.state = path.resolve()
                return dispatch({"operation": "snapshot", "state": str(self.state)})
            if op == "download_client":
                name = payload.get("name")
                if not isinstance(name, str) or not NAME.fullmatch(name) or name.startswith("desktop-run-"):
                    raise Denied("Invalid agent name")
                clients = read_json(self.state / "clients.json")
                if name not in clients:
                    raise Denied("Agent no longer exists")
                path = (self.state / f"{name}-client.json").resolve()
                if path.parent != self.state or not path.is_file():
                    raise Denied("The generated client file is not available on this host")
                config = read_json(path)
                from .security import token_hash
                if not hmac.compare_digest(token_hash(config["token"]), clients[name]["sha256"]):
                    raise Denied("The generated client file is stale")
                return config
            if op not in OPERATIONS:
                raise Denied("Unsupported web operation")
            if op in {"initialize", "save_action", "delete_action", "select_state"} and self.connection.get(session)["state"] in {"connecting", "challenge"}:
                raise Denied("Finish or cancel Keeper login before changing the workspace")
            return dispatch({**payload, "state": str(self.state)})
        finally:
            self.gate.release()

    def close(self):
        self.connection.stop()
        self.browser.stop()


def handler_for(admin):
    class Handler(BaseHTTPRequestHandler):
        server_version = "KeeperAgentWeb"
        sys_version = ""

        def log_message(self, *args):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def reply(self, code, value, *, mime="application/json", cookie=None, filename=None):
            body = value if isinstance(value, bytes) else json.dumps(value).encode()
            self.send_response(code)
            for key, val in {"Content-Type": mime, "Content-Length": str(len(body)), "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'",
                "Connection": "close"}.items():
                self.send_header(key, val)
            if cookie:
                self.send_header("Set-Cookie", cookie)
            if filename:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def valid_origin(self, mutation=False):
            if self.headers.get_all("Host", []) != [admin.authority]:
                raise Denied("Invalid host")
            if self.headers.get("Sec-Fetch-Site") not in {None, "none", "same-origin"}:
                raise Denied("Cross-origin access refused")
            origin = self.headers.get("Origin")
            if (mutation and origin != admin.origin) or (origin and origin != admin.origin):
                raise Denied("Cross-origin access refused")

        def do_GET(self):
            try:
                self.valid_origin()
                path = urlsplit(self.path).path
                if path == "/admin/session":
                    # Cookies are shared across ports on a host. A tab-scoped proof
                    # keeps a cookie captured by another localhost app insufficient.
                    _, csrf = admin.authenticate(self.headers, mutation=True)
                    self.reply(200, {"csrf": csrf})
                    return
                if path != "/" and not path.startswith("/assets/"):
                    self.reply(404, {"error": "Not found"})
                    return
                resource = admin.assets / ("index.html" if path == "/" else unquote(path).lstrip("/"))
                resource = resource.resolve()
                if not resource.is_relative_to(admin.assets) or not resource.is_file():
                    self.reply(404, {"error": "Not found"})
                    return
                content = resource.read_bytes()
                if path == "/":
                    content = content.replace(b"</head>", b'<meta name="keeper-agent-mode" content="web"></head>')
                self.reply(200, content, mime=mimetypes.guess_type(resource.name)[0] or "application/octet-stream")
            except PermissionError:
                self.reply(401, {"error": "Sign in to the administrator workspace"})
            except Exception:
                self.reply(403, {"error": "Request refused"})

        def do_POST(self):
            try:
                if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                    raise Denied("Invalid request framing")
                length = int(self.headers["Content-Length"])
                if not 0 < length <= 1048576 or self.headers.get_content_type() != "application/json":
                    raise Denied("Invalid request body")
                # Drain a strictly bounded body before replying, avoiding TCP resets on
                # Windows when a rejected request's body arrives after its headers.
                body = self.rfile.read(length)
                if len(body) != length:
                    raise Denied("Incomplete request body")
                self.valid_origin(mutation=True)
                # No JSON is interpreted and no operation runs before authentication.
                session = None
                if self.path != "/admin/login":
                    session, _ = admin.authenticate(self.headers, mutation=True)
                payload = json.loads(body)
                if not isinstance(payload, dict):
                    raise Denied("Invalid request")
                if self.path == "/admin/login":
                    session, csrf = admin.login(payload.get("key"))
                    self.reply(200, {"csrf": csrf}, cookie=f"{COOKIE}={session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800" + ("; Secure" if admin.secure else ""))
                elif self.path == "/admin/logout":
                    admin.logout(session)
                    self.reply(200, {"ok": True}, cookie=f"{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" + ("; Secure" if admin.secure else ""))
                elif self.path == "/admin/request":
                    value = admin.operation(payload, session)
                    filename = payload["name"] + "-client.json" if payload.get("operation") == "download_client" else None
                    self.reply(200, value, filename=filename)
                else:
                    self.reply(404, {"error": "Not found"})
            except PermissionError:
                self.reply(401, {"error": "Session expired. Sign in again."})
            except Denied as error:
                self.reply(403, {"error": str(error)})
            except Exception:
                self.reply(400, {"error": "Could not complete this request. Check workspace configuration and permissions."})

        def do_OPTIONS(self):
            self.reply(403, {"error": "Cross-origin access refused"})

    return Handler


class WebServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    connections = 64
    per_address = 8

    def __init__(self, address, handler):
        self.slots = threading.BoundedSemaphore(self.connections)
        self.open = {}
        self.open_lock = threading.Lock()
        self.tls = None
        super().__init__(address, handler)

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(10)
        if self.tls:
            # Handshake on the request thread: a client that never sends a
            # ClientHello must not stall the accept loop for everyone else.
            try:
                sock = self.tls.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
            except Exception:
                sock.close()
                raise
        return sock, address

    def admit(self, host):
        # Loopback clients all share one address, so only the total limit applies.
        capped = not ipaddress.ip_address(host).is_loopback
        with self.open_lock:
            if capped and self.open.get(host, 0) >= self.per_address:
                return False
            if not self.slots.acquire(blocking=False):
                return False
            self.open[host] = self.open.get(host, 0) + 1
            return True

    def release(self, host):
        with self.open_lock:
            self.open[host] -= 1
            if not self.open[host]:
                del self.open[host]
        self.slots.release()

    def process_request(self, request, client_address):
        if not self.admit(client_address[0]):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.release(client_address[0])
            raise

    def process_request_thread(self, request, client_address):
        try:
            if self.tls:
                try:
                    request.do_handshake()
                except Exception:
                    self.shutdown_request(request)
                    return
            super().process_request_thread(request, client_address)
        finally:
            self.release(client_address[0])

    def handle_error(self, request, client_address):
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(description="Serve the authenticated Keeper Agent web administrator")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--web-state", type=Path, required=True, help="Separate private folder for administrator access key")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19464)
    parser.add_argument("--origin", help="Exact browser origin (required for HTTPS or remote binding)")
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--assets", type=Path)
    args = parser.parse_args(argv)
    if bool(args.cert) != bool(args.key):
        parser.error("Provide both --cert and --key")
    if args.host != "127.0.0.1" and not args.cert:
        parser.error("Non-loopback access requires HTTPS with --cert, --key, and --origin")
    if args.cert and not args.origin:
        parser.error("HTTPS requires an explicit --origin")
    origin = args.origin or f"http://127.0.0.1:{args.port}"
    parsed = urlsplit(origin)
    if (parsed.scheme != ("https" if args.cert else "http") or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment or (not args.cert and origin != f"http://127.0.0.1:{args.port}")):
        parser.error("Origin must exactly match the web server's scheme and browser host/port, without a path")
    private = args.web_state.resolve()
    state = args.state.resolve()
    if private == state or private.is_relative_to(state) or state.is_relative_to(private):
        parser.error("Broker state and web state must be separate, non-nested folders")
    assets = args.assets or (Path(getattr(sys, "_MEIPASS", "")) / "web_assets" if getattr(sys, "frozen", False)
                             else Path(__file__).resolve().parents[1] / "desktop" / "dist")
    if not (assets / "index.html").is_file():
        parser.error("Frontend assets missing. Run npm ci and npm run build in desktop, or provide --assets.")
    private.mkdir(parents=True, mode=0o700, exist_ok=True)
    protect_directory(private)
    key_path = private / "admin-access.key"
    if not key_path.exists():
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(secrets.token_urlsafe(32))
    protect_directory(key_path)
    access_key = key_path.read_text().strip()
    if len(access_key) < 32:
        parser.error("Administrator key is invalid. Remove it and restart to create a new key.")
    admin = WebAdmin(state, assets, origin, access_key)
    with WebServer((args.host, args.port), handler_for(admin)) as server:
        if args.cert:
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.minimum_version = ssl.TLSVersion.TLSv1_2
            tls.load_cert_chain(args.cert, args.key)
            server.tls = tls
        print(f"Keeper Agent web: {origin}\nAdministrator access key file: {key_path}\nKeep this key private. Ctrl+C stops this web server and any broker it started.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            admin.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
