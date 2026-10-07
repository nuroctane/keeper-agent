"""Synthetic E2E fixture. Never imported by the production server."""
import json
from pathlib import Path
import ssl
import sys
import tempfile
import threading
import time

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root))
from keeper_agent.cli import initialize, replace_private
from keeper_agent.desktop import policy_digest
from keeper_agent.server import Broker, LocalServer, handler_for as broker_handler
from keeper_agent.web import WebAdmin, WebServer, handler_for
from keeper_agent.web_worker import BrowserLoginUi

(root / 'work').mkdir(exist_ok=True)
state = Path(tempfile.mkdtemp(prefix='web-e2e-', dir=root/'work'))/'broker'
initialize(state, 'fixture@example.invalid', 19463)
policy = {'version': 1, 'actions': {'fixture-check': {'kind': 'command', 'argv': [sys.executable, '-c', 'print("fixture")'],
          'cwd': str(state), 'env': {}, 'output': 'none'}}}
replace_private(state/'policy.json', policy)


class SyntheticProvider:
    def sync(self):
        pass


tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(state/'server.crt', state/'server.key')
broker = LocalServer(0, broker_handler(Broker(state, policy, SyntheticProvider())), tls)
replace_private(state/'server.json', {'port': broker.server_port})
replace_private(state/'broker-status.json', {'policyDigest': policy_digest(policy)})
threading.Thread(target=broker.serve_forever, daemon=True).start()
admin = WebAdmin(state, root/'desktop/dist', 'http://127.0.0.1:19465', 'synthetic-web-e2e-admin-key-only-123456789')
with WebServer(('127.0.0.1', 19465), handler_for(admin)) as server:
    print('Synthetic web test server ready', flush=True)
    try:
        server.serve_forever()
    finally:
        admin.close()
        broker.shutdown()
        broker.server_close()
