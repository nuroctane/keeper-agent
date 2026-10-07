import json
import sys
from pathlib import Path

import pytest

from keeper_agent.cli import initialize, replace_private
from keeper_agent.desktop import audit_tail, dispatch, policy_digest, snapshot
from keeper_agent.security import Denied, read_json


@pytest.fixture
def state(tmp_path):
    folder = tmp_path / "broker"
    initialize(folder, "fixture@example.invalid", 19463)
    return folder


def req(state, operation, **payload):
    return dispatch({"state": str(state), "operation": operation, **payload})


def action(tmp_path):
    return {"kind": "command", "argv": [sys.executable, "-c", "print('ok')"], "cwd": str(tmp_path),
            "env": {}, "output": "none"}


def test_empty_snapshot_does_not_create_state(tmp_path):
    folder = tmp_path / "absent"
    assert not snapshot(folder)["initialized"]
    assert not folder.exists()


def test_desktop_crud_and_grant_lifecycle(state):
    created = req(state, "save_action", name="check", action=action(state))
    assert created["actions"][0]["name"] == "check"
    assert req(state, "get_action", name="check")["kind"] == "command"
    with pytest.raises(Denied, match="already exists"):
        req(state, "save_action", name="check", action=action(state))
    result = req(state, "create_client", name="codex", actions=["check"])
    client_file = Path(result["path"])
    assert client_file.exists()
    contents = read_json(client_file)
    snapshot_json = json.dumps(req(state, "snapshot"))
    assert contents["token"] not in snapshot_json
    assert "sha256" not in snapshot_json
    assert "certificate" not in snapshot_json
    with pytest.raises(Denied, match="Revoke"):
        req(state, "delete_action", name="check")
    req(state, "revoke_client", name="codex")
    assert not client_file.exists()
    assert not req(state, "delete_action", name="check")["actions"]


def test_snapshot_only_returns_metadata(state):
    private_value = "synthetic-literal-to-never-display"
    a = {"kind": "http", "url": "https://example.com/path?secret=" + private_value,
         "headers": {"Authorization": "Bearer " + private_value},
         "secrets": {"token": {"record": "private-record-uid", "field": "password"}}}
    replace_private(state / "policy.json", {"version": 1, "actions": {"read": a}})
    result = snapshot(state)
    serialized = json.dumps(result)
    assert private_value not in serialized
    assert "private-record-uid" not in serialized
    assert result["actions"][0]["destination"] == "example.com"


def test_literal_secret_edit_rejected(state):
    a = {"kind": "http", "url": "https://example.com", "headers": {"Authorization": "Bearer fake-token"}}
    with pytest.raises(Denied, match="Keeper reference"):
        req(state, "save_action", name="bad", action=a)
    assert not snapshot(state)["actions"]


@pytest.mark.parametrize("name", ["../escape", "", "desktop-run-reserved"])
def test_invalid_names(state, name):
    with pytest.raises(Denied):
        req(state, "create_client", name=name, actions=[])


def test_bounded_audit_rejects_extra_fields_and_partial_lines(state):
    row = {"id": "fixture", "action": "check", "client": "codex", "status": "completed", "time": "2026-10-07", "secret": "never-return"}
    (state / "audit.jsonl").write_text((json.dumps(row) + "\n") * 400 + "incomplete\n")
    result = audit_tail(state)
    assert len(result) <= 200
    assert "never-return" not in json.dumps(result)


def test_failed_run_is_cleaned_up(state, monkeypatch):
    req(state, "save_action", name="check", action=action(state))
    monkeypatch.setattr("keeper_agent.desktop.online", lambda _: True)
    replace_private(state / "broker-status.json", {"policyDigest": policy_digest(read_json(state / "policy.json"))})
    def fail(*args):
        raise Denied("synthetic failure")
    monkeypatch.setattr("keeper_agent.desktop.call_client", fail)
    with pytest.raises(Denied, match="synthetic"):
        req(state, "run", name="check")
    assert read_json(state / "clients.json") == {}
    assert not list(state.glob("desktop-run-*-client.json"))


def test_policy_revision_blocks_stale_run(state, monkeypatch):
    req(state, "save_action", name="check", action=action(state))
    monkeypatch.setattr("keeper_agent.desktop.online", lambda _: True)
    replace_private(state / "broker-status.json", {"policyDigest": "old"})
    assert snapshot(state)["pendingRestart"]
    with pytest.raises(Denied, match="Restart"):
        req(state, "run", name="check")


def test_region_initialization(tmp_path):
    state = tmp_path / "eu-broker"
    result = req(state, "initialize", email="fixture@example.invalid", region="EU")
    assert result["region"] == "EU"
    assert read_json(state / "keeper.json")["server"] == "keepersecurity.eu"


def test_temporary_run_grant_expires_even_if_helper_is_interrupted(state, monkeypatch):
    from keeper_agent.server import Broker
    req(state, "save_action", name="check", action=action(state))
    monkeypatch.setattr("keeper_agent.desktop.online", lambda _: True)
    replace_private(state / "broker-status.json", {"policyDigest": policy_digest(read_json(state / "policy.json"))})
    def check_expiration(filename, body):
        token = read_json(filename)["token"]
        broker = Broker(state, read_json(state / "policy.json"), None)
        assert broker.authenticate(token)[1] == {"check"}
        clients = read_json(state / "clients.json")
        expiry = next(iter(clients.values()))["expiresAt"]
        monkeypatch.setattr("keeper_agent.server.time.time", lambda: expiry + 1)
        with pytest.raises(Denied, match="Unauthorized"):
            broker.authenticate(token)
        return {"result": "fixture"}
    monkeypatch.setattr("keeper_agent.desktop.call_client", check_expiration)
    assert req(state, "run", name="check") == {"result": "fixture"}


def test_temporary_grant_without_expiry_fails_closed(state):
    from keeper_agent.server import Broker
    from keeper_agent.security import token_hash
    token = "synthetic-" + "x" * 48
    replace_private(state / "clients.json", {"desktop-run-interrupted": {
        "sha256": token_hash(token), "actions": ["check"]}})
    with pytest.raises(Denied, match="Unauthorized"):
        Broker(state, read_json(state / "policy.json"), None).authenticate(token)


def test_desktop_run_over_real_pinned_tls(state):
    import ssl
    import threading
    from keeper_agent.server import Broker, LocalServer, handler_for
    class SyntheticProvider:
        def sync(self):
            pass
    req(state, "save_action", name="check", action=action(state))
    policy = read_json(state / "policy.json")
    broker = Broker(state, policy, SyntheticProvider())
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(state / "server.crt", state / "server.key")
    server = LocalServer(0, handler_for(broker), tls)
    replace_private(state / "server.json", {"port": server.server_port})
    replace_private(state / "broker-status.json", {"policyDigest": policy_digest(policy)})
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = req(state, "run", name="check")
        assert result["result"] == {"exit_code": 0}
        assert snapshot(state)["events"][0]["status"] == "completed"
        assert read_json(state / "clients.json") == {}
        assert not list(state.glob("desktop-run-*-client.json"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
