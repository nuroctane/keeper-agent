import json
from unittest.mock import patch
import pytest
from keeper_agent import desktop
from keeper_agent.security import Denied
from keeper_agent.server import Broker
from keeper_agent.web import WebAdmin


def test_failed_workspace_selection_preserves_previous_workspace(tmp_path):
    old = tmp_path / 'old'
    new = tmp_path / 'new'
    old.mkdir(); new.mkdir()
    for folder in (old, new):
        (folder / 'keeper.json').write_text('{}')
        (folder / 'policy.json').write_text('{"version":1,"actions":{}}')
        (folder / 'clients.json').write_text('{}')
    (old / 'server.json').write_text('{"port":19463}')
    admin = WebAdmin(old, tmp_path, 'http://127.0.0.1:19464', 'x' * 40)
    with pytest.raises(FileNotFoundError):
        admin.operation({'operation': 'select_state', 'path': str(new)}, 'session')
    assert admin.state == old


def test_cleanup_failure_preserves_completed_result(tmp_path):
    (tmp_path / 'keeper.json').write_text('{}')
    (tmp_path / 'policy.json').write_text(json.dumps({'version': 1, 'actions': {'write': {'kind': 'http', 'url': 'https://example.com'}}}))
    effects = []
    with patch.object(desktop, 'snapshot', return_value={'online': True, 'pendingRestart': False}), patch.object(desktop, 'add_client'), patch.object(desktop, 'call_client', side_effect=lambda *a: effects.append('effect') or {'result': {'status': 200}}), patch.object(desktop, 'revoke_client', side_effect=Denied('Workspace is busy. Try again shortly.', 'workspace_busy')):
        result = desktop.dispatch({'state': str(tmp_path), 'operation': 'run', 'name': 'write'})
    assert effects == ['effect']
    assert result['result']['status'] == 200
    assert 'cleanup failed' in result['warning']
    assert 'Try again' not in result['warning']


@pytest.mark.parametrize('status', ['completed', 'failed'])
def test_audit_failure_after_start_warns_about_side_effects(tmp_path, status):
    policy = {'version': 1, 'actions': {'write': {'kind': 'http', 'url': 'https://example.com'}}}
    (tmp_path / 'clients.json').write_text(json.dumps({'agent': {'actions': ['write']}}))
    broker = Broker(tmp_path, policy, None)
    effects = []
    def run(*args, **kwargs):
        effects.append('effect')
        if status == 'failed':
            raise RuntimeError('synthetic')
        return {'status': 200}
    def audit(_id, _client, _action, event):
        if event == status:
            raise OSError('synthetic audit failure')
    broker.engine.run = run
    broker.audit = audit
    with pytest.raises(Denied) as error:
        broker.invoke('agent', {'write'}, {'operation': 'run', 'action': 'write'})
    assert effects == ['effect']
    assert error.value.code == 'outcome_unknown'
    assert 'destination' in error.value.hint
