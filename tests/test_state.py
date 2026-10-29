import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from keeper_agent.cli import add_client, certificate, replace_private, revoke_client, main
from keeper_agent.desktop import dispatch
from keeper_agent.security import Denied, read_json, write_private
from keeper_agent.server import Broker
from keeper_agent.state import transaction


@pytest.fixture
def state(tmp_path):
    # Synthetic state avoids account setup/ACL subprocesses in each race test.
    certificate(tmp_path)
    write_private(tmp_path / "policy.json", {"version": 1, "actions": {
        "check": {"kind": "http", "url": "https://example.invalid"}}})
    write_private(tmp_path / "clients.json", {})
    write_private(tmp_path / "server.json", {"port": 19463})
    write_private(tmp_path / "keeper.json", {"user": "fixture@example.invalid"})
    return tmp_path


def test_concurrent_admin_saves_preserve_every_action(state):
    barrier = threading.Barrier(8)

    def save(index):
        barrier.wait(timeout=10)
        dispatch({"state": str(state), "operation": "save_action", "name": f"action-{index}",
                  "action": {"kind": "http", "url": "https://example.invalid"}})

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(save, range(8)))
    assert set(read_json(state / "policy.json")["actions"]) == {"check", *[f"action-{i}" for i in range(8)]}


def test_cli_revocation_waits_for_another_process_transaction(state):
    replace_private(state / "clients.json", {"old": {"actions": ["check"]}})
    signal = state / "ready"
    root = Path(__file__).resolve().parents[1]
    script = """
import sys
from pathlib import Path
from keeper_agent.cli import revoke_client
state = Path(sys.argv[1])
(state / 'ready').write_text('ready')
revoke_client(state, 'old')
"""
    proc = None
    try:
        with transaction(state):
            clients = read_json(state / "clients.json")
            proc = subprocess.Popen([sys.executable, "-c", script, str(state)], cwd=root,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            deadline = time.monotonic() + 10
            while not signal.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            assert signal.exists()
            with pytest.raises(subprocess.TimeoutExpired):
                proc.wait(timeout=0.2)
            clients["new"] = {"actions": ["check"]}
            replace_private(state / "clients.json", clients)
        stdout, stderr = proc.communicate(timeout=15)
        assert proc.returncode == 0, stderr.decode()
        assert set(read_json(state / "clients.json")) == {"new"}
    finally:
        if proc and proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=5)


def test_transaction_releases_on_error_and_allows_nested_edits(state):
    with pytest.raises(RuntimeError):
        with transaction(state):
            with transaction(state):
                raise RuntimeError("synthetic")
    with transaction(state):
        revoke_client(state, "absent", missing_ok=True)


def test_new_grants_expire_and_legacy_grants_remain_compatible(state, monkeypatch):
    add_client(state, "agent", ["check"], state / "agent-client.json", expires_in=3600)
    token = read_json(state / "agent-client.json")["token"]
    broker = Broker(state, read_json(state / "policy.json"), None)
    assert broker.authenticate(token) == ("agent", {"check"})
    expiry = read_json(state / "clients.json")["agent"]["expiresAt"]
    monkeypatch.setattr("keeper_agent.server.time.time", lambda: expiry)
    with pytest.raises(Denied) as failure:
        broker.authenticate(token)
    assert failure.value.code == "grant_expired"
    assert not broker.granted("agent", "check")
    clients = read_json(state / "clients.json")
    del clients["agent"]["expiresAt"]
    replace_private(state / "clients.json", clients)
    assert broker.authenticate(token) == ("agent", {"check"})


def test_status_is_authenticated_metadata_only_and_does_not_access_vault(state):
    broker = Broker(state, read_json(state / "policy.json"), None)
    assert broker.invoke("agent", {"check"}, {"operation": "status"}) == {
        "ready": True, "actions": 1, "expiresAt": None}
    replace_private(state / "policy.json", {"invalid": True})
    status = broker.invoke("agent", {"check"}, {"operation": "status"})
    assert status["ready"] is False and status["code"] == "policy_invalid"


@pytest.mark.parametrize("duration", [0, -1, True, "3600", 366 * 86400])
def test_invalid_expiry_never_issues_access(state, duration):
    with pytest.raises(Denied):
        add_client(state, "agent", ["check"], state / "agent-client.json", expires_in=duration)
    assert not (state / "agent-client.json").exists()
    assert read_json(state / "clients.json") == {}


def test_client_errors_are_structured_without_sdk_details(state, monkeypatch, capsys):
    import httpx
    from keeper_agent.cli import call_client
    add_client(state, "agent", ["check"], state / "agent-client.json")
    capsys.readouterr()
    monkeypatch.setattr(httpx.Client, "post", lambda *a, **kw: (_ for _ in ()).throw(httpx.ConnectError("private upstream details")))
    result = main(["status", "--client", str(state / "agent-client.json"), "--json"])
    assert result == 1
    payload = json.loads(capsys.readouterr().err)
    assert payload["code"] == "broker_offline"
    assert "private upstream details" not in json.dumps(payload)
    monkeypatch.setattr(httpx.Client, "post", lambda *a, **kw: (_ for _ in ()).throw(httpx.ReadTimeout("private upstream details")))
    with pytest.raises(Denied) as failure:
        call_client(state / "agent-client.json", {"operation": "run", "action": "check"})
    assert failure.value.code == "outcome_unknown"


def test_grant_expiry_snapshot_and_atomic_temporary_grant(state, monkeypatch):
    monkeypatch.setattr("keeper_agent.desktop.online", lambda _: False)
    result = dispatch({"operation": "create_client", "state": str(state), "name": "agent",
                       "actions": ["check"], "expiresIn": 3600})
    client = result["snapshot"]["clients"][0]
    assert client["expiresAt"] > time.time() and not client["expired"]
    add_client(state, "desktop-run-test", ["check"], state / "temporary-client.json", expires_in=360, temporary=True)
    grant = read_json(state / "clients.json")["desktop-run-test"]
    assert grant["desktopTemporary"] and grant["expiresAt"] > time.time()


def test_replacing_a_named_agent_does_not_authorize_its_old_queued_token(state):
    from keeper_agent.security import token_hash
    from unittest.mock import Mock
    add_client(state, "agent", ["check"], state / "agent-client.json")
    old_token = read_json(state / "agent-client.json")["token"]
    broker = Broker(state, read_json(state / "policy.json"), None)
    name, allowed = broker.authenticate(old_token)
    # The request authenticated before replacement but has not begun execution.
    revoke_client(state, "agent")
    add_client(state, "agent", ["check"], state / "agent-client.json")
    broker.engine.run = Mock(return_value={"status": 200})
    with pytest.raises(Denied):
        broker.invoke(name, allowed, {"operation": "run", "action": "check"}, credential=token_hash(old_token))
    broker.engine.run.assert_not_called()
    assert not (state / "audit.jsonl").exists()
    new_token = read_json(state / "agent-client.json")["token"]
    assert broker.invoke(name, allowed, {"operation": "run", "action": "check"},
                         credential=token_hash(new_token))["result"] == {"status": 200}


def test_revocation_preserves_a_conventional_file_owned_by_another_grant(state):
    # CLI output paths are configurable; the filename alone does not prove who
    # owns the credential inside it.
    add_client(state, "other", ["check"], state / "agent-client.json")
    add_client(state, "agent", ["check"], state / "custom-client.json")
    other_file = (state / "agent-client.json").read_bytes()
    dispatch({"operation": "revoke_client", "state": str(state), "name": "agent"})
    assert (state / "agent-client.json").read_bytes() == other_file
    assert set(read_json(state / "clients.json")) == {"other"}


def test_queued_action_expires_before_it_can_start_later(state):
    from unittest.mock import Mock
    add_client(state, "agent", ["check"], state / "agent-client.json")
    broker = Broker(state, read_json(state / "policy.json"), None)
    broker.queue_timeout = 0.02
    broker.engine.run = Mock(return_value={"status": 200})
    outcomes = []
    for _ in range(broker.concurrency):
        broker.slots.acquire()

    def run():
        try:
            outcomes.append(broker.invoke("agent", {"check"}, {"operation": "run", "action": "check"}))
        except Denied as error:
            outcomes.append(error)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        thread.join(timeout=0.3)
    finally:
        for _ in range(broker.concurrency):
            broker.slots.release()
        thread.join(timeout=5)
    assert len(outcomes) == 1 and isinstance(outcomes[0], Denied)
    assert outcomes[0].code == "queue_timeout"
    broker.engine.run.assert_not_called()
    assert not (state / "audit.jsonl").exists()
    assert broker.invoke("agent", {"check"}, {"operation": "run", "action": "check"})["result"] == {"status": 200}
