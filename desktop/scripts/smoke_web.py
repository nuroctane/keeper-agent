"""Check a frozen web distribution with synthetic state and a generated admin key."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time

import httpx

parser = argparse.ArgumentParser()
parser.add_argument('core', type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
(root/'work').mkdir(exist_ok=True)
scratch = Path(tempfile.mkdtemp(prefix='frozen-web-', dir=root/'work'))
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
origin = f'http://127.0.0.1:{port}'
process = subprocess.Popen([str(args.core.resolve()), 'web', '--state', str(scratch/'broker'),
    '--web-state', str(scratch/'admin'), '--port', str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    with httpx.Client(base_url=origin, trust_env=False, headers={'Origin':origin}) as client:
        deadline = time.monotonic()+30
        while True:
            try:
                page = client.get('/')
                assert 'name="keeper-agent-mode"' in page.text
                break
            except httpx.TransportError:
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('Packaged web server did not become ready')
                time.sleep(.25)
        assert client.get('/admin/session').status_code == 401
        key = (scratch/'admin/admin-access.key').read_text().strip()
        response = client.post('/admin/login', json={'key':key})
        assert response.status_code == 200
        client.headers['X-CSRF-Token'] = response.json()['csrf']
        assert client.get('/admin/session').status_code == 200
        proof = client.headers.pop('X-CSRF-Token')
        assert client.get('/admin/session').status_code == 403
        client.headers['X-CSRF-Token'] = proof
        response = client.post('/admin/request', json={'operation':'snapshot'})
        assert response.status_code == 200 and not response.json()['initialized']
        assert client.post('/admin/logout', json={}).status_code == 200
        assert client.get('/admin/session').status_code == 401
    print(json.dumps({'passed':True,'packagedWeb':True,'assets':True,'authenticatedSession':True}))
finally:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)

# Load the frozen login worker and fail locally before any Keeper network access.
worker = subprocess.run([str(args.core.resolve()), 'web-worker', '--state', str(scratch/'missing')],
    capture_output=True, text=True, timeout=30)
assert worker.returncode == 1
assert json.loads(worker.stdout)['state'] == 'failed'
assert not worker.stderr
assert str(scratch) not in worker.stdout
print(json.dumps({'passed':True,'packagedLoginWorker':True,'sanitizedFailure':True}))
