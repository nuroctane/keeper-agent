import json
from pathlib import Path
import threading
from unittest.mock import Mock

import httpx
import pytest

from keeper_agent.security import Denied
from keeper_agent.web import WebAdmin, WebServer, handler_for
from keeper_agent.web_worker import BrowserLoginUi


@pytest.fixture
def web(tmp_path):
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "index.html").write_text('<html><head></head><body>app</body></html>')
    (tmp_path / "private.txt").write_text('synthetic-private')
    admin = WebAdmin(tmp_path / "broker", assets, "http://127.0.0.1:0", "synthetic-admin-" + "x" * 40)
    server = WebServer(("127.0.0.1", 0), handler_for(admin))
    admin.origin = f"http://127.0.0.1:{server.server_port}"
    admin.authority = f"127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    with httpx.Client(base_url=admin.origin, trust_env=False, headers={"Origin": admin.origin}) as client:
        yield admin, client
    server.shutdown()
    server.server_close()
    admin.close()
    thread.join(timeout=5)


def login(client):
    response = client.post('/admin/login', json={"key": "synthetic-admin-" + "x" * 40})
    assert response.status_code == 200
    cookie = response.headers['set-cookie']
    assert 'HttpOnly' in cookie and 'SameSite=Strict' in cookie
    client.headers['X-CSRF-Token'] = response.json()['csrf']
    return response


def op(client, operation, **payload):
    return client.post('/admin/request', json={"operation": operation, **payload})


def test_browser_assets_do_not_disclose_private_files(web):
    admin, client = web
    page = client.get('/')
    assert 'name="keeper-agent-mode"' in page.text
    assert page.headers['x-frame-options'] == 'DENY'
    assert "frame-ancestors 'none'" in page.headers['content-security-policy']
    for path in ['/keeper.json', '/admin-access.key', '/assets/%2e%2e/%2e%2e/private.txt']:
        assert client.get(path).status_code == 404
    assert client.get('/admin/session').status_code == 401
    assert op(client, 'snapshot').status_code == 401


def test_host_origin_and_csrf_are_all_required(web):
    admin, client = web
    assert client.post('/admin/login', json={"key": "anything"}, headers={"Origin": "https://evil.invalid"}).status_code == 403
    assert client.get('/', headers={"Host": "evil.invalid"}).status_code == 403
    assert client.options('/admin/request').status_code == 403
    login(client)
    assert op(client, 'snapshot').status_code == 200
    assert client.post('/admin/request', json={"operation": "snapshot"}, headers={"X-CSRF-Token": "bad"}).status_code == 403
    assert client.post('/admin/request', json={"operation": "snapshot"}, headers={"Sec-Fetch-Site": "same-site"}).status_code == 403
    headers = dict(client.headers)
    del headers['origin']
    with httpx.Client(base_url=admin.origin, trust_env=False, cookies=client.cookies, headers=headers) as other:
        assert op(other, 'snapshot').status_code == 403


def test_web_crud_download_revoke_and_authoritative_state(web, tmp_path):
    admin, client = web
    login(client)
    assert op(client, 'initialize', email='fixture@example.invalid', region='US').status_code == 200
    assert op(client, 'snapshot', state=str(tmp_path / 'spoofed')).json()['statePath'] == str(admin.state)
    action = {"kind": "http", "url": "https://example.invalid", "headers": {"Authorization": "Bearer {{token}}"},
              "secrets": {"token": {"record": "synthetic", "field": "password"}}}
    assert op(client, 'save_action', name='fixture', action=action).status_code == 200
    assert op(client, 'create_client', name='agent', actions=['fixture']).status_code == 200
    download = op(client, 'download_client', name='agent')
    assert download.status_code == 200
    assert download.headers['content-disposition'] == 'attachment; filename="agent-client.json"'
    token = download.json()['token']
    assert token not in op(client, 'snapshot').text
    assert op(client, 'download_client', name='../escape').status_code == 403
    assert op(client, 'delete_action', name='fixture').status_code == 403
    assert op(client, 'revoke_client', name='agent').status_code == 200
    assert op(client, 'download_client', name='agent').status_code == 403
    assert op(client, 'delete_action', name='fixture').status_code == 200


def test_logout_and_expiry_revoke_session(web, monkeypatch):
    admin, client = web
    login(client)
    assert client.post('/admin/logout', json={}).status_code == 200
    assert op(client, 'snapshot').status_code == 401
    login(client)
    for session in admin.sessions.values():
        session['seen'] -= 1801
    assert op(client, 'snapshot').status_code == 401


def test_login_throttle_and_secure_cookie(web):
    admin, client = web
    for _ in range(10):
        assert client.post('/admin/login', json={"key": "wrong"}).status_code == 403
    assert 'Wait one minute' in client.post('/admin/login', json={"key": "wrong"}).text
    admin.attempts.clear()
    admin.secure = True
    assert '; Secure' in login(client).headers['set-cookie']


def test_login_ui_never_emits_submitted_password():
    events = []
    secret = 'synthetic-password-never-return'
    def receive():
        return {"id": events[-1]['challenge']['id'], "action": "password", "value": secret}
    step = Mock()
    BrowserLoginUi(events.append, receive).on_password(step)
    step.verify_password.assert_called_once_with(secret)
    assert secret not in json.dumps(events)


def test_login_challenge_replay_and_error_redaction():
    events = []
    ui = BrowserLoginUi(events.append, lambda: {"id": "expired", "action": "password", "value": "synthetic"})
    with pytest.raises(Denied, match="expired"):
        ui.on_password(Mock())
    def receive():
        return {"id": events[-1]['challenge']['id'], "action": "password", "value": "synthetic"}
    step = Mock()
    step.verify_password.side_effect = RuntimeError('do-not-expose-upstream')
    with pytest.raises(Denied) as error:
        BrowserLoginUi(events.append, receive).on_password(step)
    assert 'do-not-expose-upstream' not in str(error.value)


def test_remote_http_fails_closed(tmp_path):
    from keeper_agent.web import main
    with pytest.raises(SystemExit):
        main(['--state', str(tmp_path/'state'), '--web-state', str(tmp_path/'web'), '--host', '0.0.0.0'])


def test_login_answer_is_bound_to_owner_and_nonce():
    from keeper_agent.web import Worker
    worker = Worker()
    worker.owner = 'owner'
    worker.status = {"state": "challenge", "challenge": {"id": "nonce", "options": [{"id": "password"}]}}
    assert worker.get('other') == {"state": "other-session"}
    for owner, nonce in [('other', 'nonce'), ('owner', 'old')]:
        with pytest.raises(Denied):
            worker.answer(owner, {"id": nonce, "action": "password", "value": "synthetic"})


def test_stopping_finished_worker_never_signals_reused_pid(monkeypatch):
    from keeper_agent.web import Worker
    process_lookup = Mock()
    monkeypatch.setattr('psutil.Process', process_lookup)
    worker = Worker()
    proc = Mock()
    proc.poll.return_value = 0
    worker.process = proc
    worker.stop()
    process_lookup.assert_not_called()
    proc.stdin.close.assert_called_once()
    assert worker.get('owner') == {'state': 'idle'}


def test_device_approval_and_mfa_keep_secrets_out_of_challenges():
    from keepercommander.auth.login_steps import DeviceApprovalChannel, TwoFactorChannel, TwoFactorChannelInfo, TwoFactorDuration
    events = []
    secret = 'synthetic-code'
    answer_action = 'email-code'
    def receive():
        return {"id": events[-1]['challenge']['id'], "action": answer_action, "value": secret}
    ui = BrowserLoginUi(events.append, receive)
    device = Mock()
    ui.on_device_approval(device)
    device.send_code.assert_called_once_with(DeviceApprovalChannel.Email, secret)
    channel = TwoFactorChannelInfo()
    channel.channel_type = TwoFactorChannel.Authenticator
    channel.channel_uid = b'synthetic-channel'
    mfa = Mock()
    mfa.get_channels.return_value = [channel]
    answer_action = '0'
    ui.on_two_factor(mfa)
    mfa.send_code.assert_called_once_with(b'synthetic-channel', secret)
    assert mfa.duration == TwoFactorDuration.EveryLogin
    assert secret not in json.dumps(events)


def test_concurrent_mutation_is_rejected_and_state_switch_is_validated(web, tmp_path):
    admin, client = web
    login(client)
    with admin.gate:
        assert op(client, 'initialize', email='test@example.invalid', region='US').status_code == 403
    assert op(client, 'select_state', path=str(tmp_path/'absent')).status_code == 403
    assert op(client, 'select_state', path='relative-folder').status_code == 403


def test_web_server_https_uses_secure_cookie_and_same_origin(tmp_path):
    import ssl
    from keeper_agent.cli import certificate
    certificate(tmp_path)
    assets = tmp_path/'assets'
    assets.mkdir()
    (assets/'index.html').write_text('<head></head>')
    admin = WebAdmin(tmp_path/'broker', assets, 'https://127.0.0.1:0', 'synthetic-admin-'+'x'*40)
    server = WebServer(('127.0.0.1',0), handler_for(admin))
    server.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.tls.load_cert_chain(tmp_path/'server.crt', tmp_path/'server.key')
    admin.origin = f'https://127.0.0.1:{server.server_port}'
    admin.authority = f'127.0.0.1:{server.server_port}'
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    trust = ssl.create_default_context(cafile=str(tmp_path/'server.crt'))
    try:
        with httpx.Client(base_url=admin.origin, verify=trust, trust_env=False, headers={'Origin':admin.origin}) as client:
            response = login(client)
            assert '; Secure' in response.headers['set-cookie']
            assert op(client,'snapshot').status_code == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
