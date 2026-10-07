from __future__ import annotations

import hmac
import json
import socket
import ssl
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

from .engine import Engine
from .security import Denied, read_json, token_hash


class Broker:
    def __init__(self, state, policy, provider):
        self.state = state
        self.engine = Engine(policy, provider)

    def authenticate(self, token):
        if not isinstance(token, str) or not 32 <= len(token) <= 200:
            raise Denied("Unauthorized")
        digest = token_hash(token)
        clients = read_json(self.state / "clients.json")
        for name, client in clients.items():
            if hmac.compare_digest(client["sha256"], digest):
                return name, set(client["actions"])
        raise Denied("Unauthorized")

    def audit(self, request_id, client, action, status):
        entry = {"time": datetime.now(timezone.utc).isoformat(), "id": request_id,
                 "client": client, "action": action, "status": status}
        with (self.state / "audit.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry) + "\n")
            stream.flush()

    def invoke(self, client, allowed, body):
        actions = self.engine.policy["actions"]
        if body == {"operation": "list"}:
            return {"actions": [{"name": name, "kind": actions[name]["kind"],
                                  "description": actions[name].get("description", "")}
                                 for name in sorted(allowed & actions.keys())]}
        if not isinstance(body, dict) or set(body) != {"operation", "action"} or body["operation"] != "run":
            raise Denied("Expected a named action; custom arguments are not accepted")
        name = body["action"]
        if not isinstance(name, str) or name not in allowed or name not in actions:
            raise Denied("Action not permitted")
        request_id = str(uuid.uuid4())
        self.audit(request_id, client, name, "started")
        try:
            result = self.engine.run(name)
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


class LocalServer(HTTPServer):
    # Serial execution: Commander state and browser actions are never shared concurrently.
    def __init__(self, port, handler, tls):
        self.tls = tls
        super().__init__(("127.0.0.1", port), handler)

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(5)
        try:
            return self.tls.wrap_socket(sock, server_side=True), address
        except Exception:
            sock.close()
            raise

    def handle_error(self, request, client_address):
        # Never print request bodies or a credential-bearing traceback.
        pass


def serve(state, policy, provider):
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(state / "server.crt", state / "server.key")
    config = read_json(state / "server.json")
    broker = Broker(state, policy, provider)
    with LocalServer(config["port"], handler_for(broker), tls) as server:
        print(f"Keeper Agent listening on https://127.0.0.1:{server.server_port}. Ctrl+C to lock.", flush=True)
        try:
            server.serve_forever()
        finally:
            provider.close()
