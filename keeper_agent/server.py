from __future__ import annotations

import hmac
import json
import socket
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .engine import Engine
from .policy import validate
from .security import Denied, read_json, token_hash


class Broker:
    # Actions that may execute at once. Commander access is separately serialized.
    concurrency = 4

    def __init__(self, state, policy, provider):
        self.state = state
        self.engine = Engine(policy, provider)
        self.slots = threading.BoundedSemaphore(self.concurrency)
        self.vault = threading.Lock()
        self.audit_lock = threading.Lock()
        self.reloading = threading.Lock()
        self.policy_path = state / "policy.json"
        self.status_path = state / "broker-status.json"
        # Hot reload watches the file the broker started from; the first refresh
        # rereads it so an edit made during startup is not missed. A broker built
        # from an in-memory policy (no file) keeps that policy.
        self.policy_stamp = "startup" if self.policy_path.exists() else None
        self.policy_error = False

    def stamp(self):
        try:
            info = self.policy_path.stat()
            return info.st_mtime_ns, info.st_size
        except FileNotFoundError:
            return "missing"

    def publish_status(self):
        from .cli import replace_private
        from .desktop import policy_digest
        replace_private(self.status_path, {"policyDigest": None if self.policy_error
                                           else policy_digest(self.engine.policy)})

    def refresh(self):
        """Apply policy.json edits without a restart. An invalid or missing file fails
        closed: no action runs until it is valid again, so a broken edit can never
        leave a removed action live."""
        if self.policy_stamp is None:
            return
        with self.reloading:
            stamp = self.stamp()
            if stamp == self.policy_stamp:
                return
            self.policy_stamp = stamp
            try:
                policy = validate(read_json(self.policy_path))
            except Exception:
                self.policy_error = True
            else:
                self.engine.policy = policy
                self.policy_error = False
            self.publish_status()

    def current_policy(self):
        self.refresh()
        if self.policy_error:
            raise Denied("Broker policy is invalid; fix policy.json")
        return self.engine.policy

    def authenticate(self, token):
        if not isinstance(token, str) or not 32 <= len(token) <= 200:
            raise Denied("Unauthorized")
        digest = token_hash(token)
        clients = read_json(self.state / "clients.json")
        for name, client in clients.items():
            if hmac.compare_digest(client["sha256"], digest):
                if not self.live(name, client):
                    raise Denied("Unauthorized")
                return name, set(client["actions"])
        raise Denied("Unauthorized")

    @staticmethod
    def live(name, client):
        default_expiry = 0 if name.startswith("desktop-run-") else float("inf")
        return client.get("expiresAt", default_expiry) > time.time()

    def granted(self, name, action):
        # Rechecked when a queued run starts, so revoking a client also stops
        # runs that were waiting for a slot, not only later requests.
        client = read_json(self.state / "clients.json").get(name)
        return bool(client) and self.live(name, client) and action in client["actions"]

    def audit(self, request_id, client, action, status):
        entry = {"time": datetime.now(timezone.utc).isoformat(), "id": request_id,
                 "client": client, "action": action, "status": status}
        with self.audit_lock, (self.state / "audit.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry) + "\n")
            stream.flush()

    def invoke(self, client, allowed, body):
        if body == {"operation": "list"}:
            actions = self.current_policy()["actions"]
            return {"actions": [{"name": name, "kind": actions[name]["kind"],
                                  "description": actions[name].get("description", "")}
                                 for name in sorted(allowed & actions.keys())]}
        if not isinstance(body, dict) or set(body) != {"operation", "action"} or body["operation"] != "run":
            raise Denied("Expected a named action; custom arguments are not accepted")
        name = body["action"]
        if not isinstance(name, str) or name not in allowed:
            raise Denied("Action not permitted")
        request_id = str(uuid.uuid4())
        with self.slots:
            # Resolve the policy and grant after waiting for a slot, so an action
            # removed, changed or revoked meanwhile never runs from stale state.
            policy = self.current_policy()
            if name not in policy["actions"] or not self.granted(client, name):
                raise Denied("Action not permitted")
            self.audit(request_id, client, name, "started")
            try:
                result = self.engine.run(name, policy, vault=self.vault)
            except Exception:
                self.audit(request_id, client, name, "failed")
                # SDK, HTTP and browser exceptions can include credentials or filled values.
                raise Denied("Action failed; inspect policy and authentication in the admin terminal") from None
            self.audit(request_id, client, name, "completed")
        return {"action": name, "request_id": request_id, "result": result}


def handler_for(broker):
    class Handler(BaseHTTPRequestHandler):
        server_version = "KeeperAgent"
        sys_version = ""

        def log_message(self, *args):
            pass

        def send_error(self, code, message=None, explain=None):
            self.reply(code, {"error": "Request rejected"})

        def reply(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True

        def do_POST(self):
            try:
                if self.path != "/v1" or self.headers.get("Origin") is not None:
                    self.reply(403, {"error": "Request rejected"})
                    return
                auth = self.headers.get("Authorization", "")
                try:
                    if not auth.startswith("Bearer "):
                        raise Denied("Unauthorized")
                    name, allowed = broker.authenticate(auth[7:])
                except Exception:
                    self.reply(401, {"error": "Unauthorized"})
                    return
                if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                    raise Denied("Invalid request framing")
                size = int(self.headers["Content-Length"])
                if not 0 < size <= 1024 or self.headers.get_content_type() != "application/json":
                    raise Denied("Invalid request body")
                data = self.rfile.read(size)
                if len(data) != size:
                    raise Denied("Incomplete request body")
                result = broker.invoke(name, allowed, json.loads(data))
                self.reply(200, result)
            except Denied as error:
                self.reply(403, {"error": str(error)})
            except Exception:
                self.reply(400, {"error": "Request failed"})
    return Handler


class LocalServer(ThreadingHTTPServer):
    # Concurrent connections keep the broker reachable while an action runs;
    # Broker.running still executes actions one at a time.
    daemon_threads = True

    def __init__(self, port, handler, tls):
        self.tls = tls
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(("127.0.0.1", port), handler)

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(5)
        try:
            # Handshake on the request thread so an idle client cannot stall accepts.
            return self.tls.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), address
        except Exception:
            sock.close()
            raise

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            try:
                request.do_handshake()
            except Exception:
                self.shutdown_request(request)
                return
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # Never print request bodies or a credential-bearing traceback.
        pass


def serve(state, policy, provider, ready=None):
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(state / "server.crt", state / "server.key")
    config = read_json(state / "server.json")
    broker = Broker(state, policy, provider)
    stopped = threading.Event()

    def watch():
        # Publish policy edits promptly so the administrator sees them applied,
        # not only when the next agent request arrives.
        while not stopped.wait(1):
            try:
                broker.refresh()
            except OSError:
                pass

    with LocalServer(config["port"], handler_for(broker), tls) as server:
        broker.refresh()
        broker.publish_status()
        print(f"Keeper Agent listening on https://127.0.0.1:{server.server_port}. Ctrl+C to lock.", flush=True)
        threading.Thread(target=watch, daemon=True).start()
        if ready:
            ready()
        try:
            server.serve_forever()
        finally:
            stopped.set()
            provider.close()
            broker.status_path.unlink(missing_ok=True)
