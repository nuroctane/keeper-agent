import base64
import json
import os
import ssl
import sys
import threading
from pathlib import Path

import httpx
import pytest

from keeper_agent.cli import certificate, call_client
from keeper_agent.engine import Engine, render
from keeper_agent.policy import validate
from keeper_agent.security import Denied, origin, scrub, token_hash, write_private
from keeper_agent.server import Broker, LocalServer, handler_for


SECRET = "fixture-secret-ONLY-123!"


class FakeProvider:
    def sync(self):
        pass

    def get(self, ref):
        assert ref["record"] == "fixture"
        return SECRET


def command(tmp_path, code, output="text"):
    return {"kind": "command", "argv": [sys.executable, "-c", code], "cwd": str(tmp_path),
            "env": {"FIXTURE": "{{key}}"}, "output": output,
            "secrets": {"key": {"record": "fixture", "field": "password"}}}


def policy(action):
    return validate({"version": 1, "actions": {"test": action}})


def test_fixed_command_injection_and_redaction(tmp_path):
    a = command(tmp_path, "import os,base64; s=os.environ['FIXTURE']; print(s); print(base64.b64encode(s.encode()).decode())")
    result = Engine(policy(a), FakeProvider()).run("test")
    assert result["exit_code"] == 0
    assert SECRET not in result["output"]
    assert result["output"].count("[REDACTED]") == 2


def test_default_command_output_suppressed(tmp_path):
    a = command(tmp_path, "import os; print(os.environ['FIXTURE'])", "none")
    assert Engine(policy(a), FakeProvider()).run("test") == {"exit_code": 0}


def test_parent_environment_not_forwarded(tmp_path, monkeypatch):
    monkeypatch.setenv("BROKER_PRIVATE_KEY", "do-not-inherit")
    a = command(tmp_path, "import os; print('BROKER_PRIVATE_KEY' in os.environ)")
    assert "False" in Engine(policy(a), FakeProvider()).run("test")["output"]


def test_command_timeout_and_limit(tmp_path):
    a = command(tmp_path, "import time; time.sleep(5)")
    a["timeout"] = 1
    with pytest.raises(Denied, match="timed out"):
        Engine(policy(a), FakeProvider()).run("test")
    a = command(tmp_path, "print('a' * 300000)")
    with pytest.raises(Denied, match="limits"):
        Engine(policy(a), FakeProvider()).run("test")


@pytest.mark.parametrize("url", ["http://example.com", "https://user:pass@example.com", "file:///etc/passwd", "https://example.com/#secret"])
def test_reject_unsafe_urls(url):
    with pytest.raises(Denied):
        policy({"kind": "http", "url": url})


def test_policy_rejects_args_secrets_and_shell_script(tmp_path):
    a = command(tmp_path, "print(1)")
    a["argv"].append("{{key}}")
    with pytest.raises(Denied):
        policy(a)
    a["argv"] = [str(tmp_path / "evil.cmd")]
    with pytest.raises(Denied):
        policy(a)


def test_unknown_keys_and_alias_fail_closed():
    with pytest.raises(Denied):
        policy({"kind": "http", "url": "https://example.com", "allow_redirects": True})
    with pytest.raises(Denied):
        render("{{not-granted}}", {})


def test_http_redirect_never_followed(monkeypatch):
    requests = []
    def respond(request):
        requests.append(request)
        return httpx.Response(302, headers={"location": "https://other.invalid"})
    factory = httpx.Client
    monkeypatch.setattr("keeper_agent.engine.httpx.Client", lambda **kw: factory(transport=httpx.MockTransport(respond), **kw))
    a = {"kind": "http", "url": "https://example.com", "headers": {"Authorization": "Bearer {{key}}"},
         "secrets": {"key": {"record": "fixture", "field": "password"}}}
    with pytest.raises(Denied, match="redirect"):
        Engine(policy(a), FakeProvider()).run("test")
    assert len(requests) == 1
    assert requests[0].headers["Authorization"] == f"Bearer {SECRET}"


def test_http_projection_and_response_redaction(monkeypatch):
    factory = httpx.Client
    def respond(request):
        return httpx.Response(200, json={"safe": {"name": "david", "echo": SECRET}, "unselected": "private"})
    monkeypatch.setattr("keeper_agent.engine.httpx.Client", lambda **kw: factory(transport=httpx.MockTransport(respond), **kw))
    a = {"kind": "http", "url": "https://example.com", "outputs": {"user": "safe.name", "echo": "safe.echo"},
         "secrets": {"key": {"record": "fixture", "field": "password"}}}
    result = Engine(policy(a), FakeProvider()).run("test")
    assert result == {"status": 200, "data": {"user": "david", "echo": "[REDACTED]"}}


def test_browser_origins_and_fill_policy():
    a = {"kind": "browser", "origins": ["https://example.com"],
         "steps": [{"op": "goto", "url": "https://evil.invalid"}]}
    with pytest.raises(Denied):
        policy(a)
    a["steps"] = [{"op": "fill", "selector": "{{key}}", "value": "x"}]
    with pytest.raises(Denied):
        policy(a)


def test_broker_errors_never_echo_provider_exception(tmp_path):
    a = {"kind": "http", "url": "https://example.com", "secrets": {"key": {"record": "fixture", "field": "password"}}}
    class Broken(FakeProvider):
        def get(self, ref):
            raise RuntimeError(SECRET)
    broker = Broker(tmp_path, policy(a), Broken())
    grant(tmp_path, ["test"])
    with pytest.raises(Denied) as error:
        broker.invoke("agent", {"test"}, {"operation": "run", "action": "test"})
    assert SECRET not in str(error.value)
    audit = (tmp_path / "audit.jsonl").read_text()
    assert SECRET not in audit
    assert '"failed"' in audit


def test_client_cannot_supply_args_or_access_ungranted_action(tmp_path):
    broker = Broker(tmp_path, policy(command(tmp_path, "print(1)")), FakeProvider())
    grant(tmp_path, ["test"])
    for body in [{"operation": "run", "action": "test", "argv": ["bad"]},
                 {"operation": "run", "action": "other"}, {"operation": "get", "record": "fixture"}]:
        with pytest.raises(Denied):
            broker.invoke("agent", {"test"}, body)
    assert broker.invoke("agent", set(), {"operation": "list"}) == {"actions": []}


def test_real_tls_client_auth_run_and_revocation(tmp_path):
    certificate(tmp_path)
    token = "test-client-" + "x" * 48
    write_private(tmp_path / "clients.json", {"agent": {"sha256": token_hash(token), "actions": ["test"]}})
    broker = Broker(tmp_path, policy(command(tmp_path, "print('passed')")), FakeProvider())
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(tmp_path / "server.crt", tmp_path / "server.key")
    server = LocalServer(0, handler_for(broker), tls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = {"url": f"https://127.0.0.1:{server.server_port}/v1", "token": token,
              "certificate": (tmp_path / "server.crt").read_text()}
    path = tmp_path / "client.json"
    write_private(path, config)
    try:
        assert call_client(path, {"operation": "list"})["actions"][0]["name"] == "test"
        result = call_client(path, {"operation": "run", "action": "test"})
        assert result["result"]["output"].strip() == "passed"
        with httpx.Client(trust_env=False) as client:
            with pytest.raises(httpx.ConnectError):
                client.post(config["url"], json={"operation": "list"})
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=config["certificate"])
        with httpx.Client(verify=context, trust_env=False) as client:
            assert client.post(config["url"], json={"operation": "list"}).status_code == 401
            assert client.post(config["url"], json={"operation": "list"},
                               headers={"Authorization": f"Bearer {token}", "Origin": "https://evil.invalid"}).status_code == 403
        (tmp_path / "clients.json").write_text("{}")
        with pytest.raises(Denied, match="Unauthorized"):
            call_client(path, {"operation": "list"})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_personal_vault_legacy_and_typed_fields():
    from keepercommander.params import KeeperParams
    from keepercommander.vault import KeeperRecord, PasswordRecord, TypedRecord, TypedField, CustomField
    from keeper_agent.provider import KeeperProvider
    from unittest.mock import patch
    provider = object.__new__(KeeperProvider)
    provider.params = KeeperParams()
    record = PasswordRecord()
    record.password = SECRET
    record.custom = [CustomField({"name": "api_key", "value": SECRET})]
    with patch.object(KeeperRecord, "load", return_value=record):
        assert provider.get({"record": "fixture", "field": "password"}) == SECRET
        assert provider.get({"record": "fixture", "field": "custom:api_key"}) == SECRET
    typed = TypedRecord()
    typed.fields = [TypedField.new_field("password", SECRET)]
    with patch.object(KeeperRecord, "load", return_value=typed):
        assert provider.get({"record": "fixture", "field": "password"}) == SECRET
        typed.fields.append(TypedField.new_field("password", "other"))
        with pytest.raises(Denied):
            provider.get({"record": "fixture", "field": "password"})
    provider.close()


def test_admin_init_and_client_file_permissions(tmp_path):
    from keeper_agent.cli import initialize, add_client, main
    from keeper_agent.security import read_json
    state = tmp_path / "private"
    initialize(state, "fixture@example.invalid", 19463)
    with pytest.raises(Denied):
        initialize(state, "fixture@example.invalid", 19463)
    (state / "policy.json").write_text(json.dumps(policy(command(tmp_path, "print('ok')"))))
    client = state / "client.json"
    with pytest.raises(Denied, match="private broker state"):
        add_client(state, "fixture", ["test"], tmp_path / "outside.json")
    add_client(state, "fixture", ["test"], client)
    # Regression: inheritance-only Windows ACL entries made token files unreadable.
    assert len(read_json(client)["token"]) >= 48
    assert "token" not in read_json(state / "clients.json")["fixture"]
    assert main(["client-revoke", "--state", str(state), "--name", "fixture"]) == 0
    assert read_json(state / "clients.json") == {}


def test_totp_is_injected_and_redacted(tmp_path):
    import pyotp
    seed = "JBSWY3DPEHPK3PXP"
    class TOTPProvider(FakeProvider):
        def get(self, ref):
            return seed
    a = command(tmp_path, "import os; s=os.environ['FIXTURE']; assert s.isdigit() and len(s)==6; print(s)")
    a["secrets"]["key"]["transform"] = "totp"
    result = Engine(policy(a), TOTPProvider()).run("test")
    assert result["exit_code"] == 0
    assert result["output"].strip() == "[REDACTED]"


def test_undeclared_placeholder_rejected_at_validation(tmp_path):
    action = command(tmp_path, "print('x')")
    action["env"]["OTHER"] = "{{undeclared}}"
    with pytest.raises(Denied, match="undeclared secret alias"):
        policy(action)
    with pytest.raises(Denied, match="undeclared secret alias"):
        policy({"kind": "http", "url": "https://example.com", "json": {"a": ["{{missing}}"]}})
    policy({"kind": "http", "url": "https://example.com", "headers": {"Authorization": "Bearer {{t}}"},
            "secrets": {"t": {"record": "fixture", "field": "password"}}})


def test_broker_stays_reachable_while_an_action_runs(tmp_path):
    import socket
    import time
    from keeper_agent.desktop import online
    certificate(tmp_path)
    write_private(tmp_path / "server.json", {"port": 0})
    token = "test-client-" + "x" * 48
    write_private(tmp_path / "clients.json", {"agent": {"sha256": token_hash(token), "actions": ["test"]}})
    broker = Broker(tmp_path, policy(command(tmp_path, "import time; time.sleep(3)", output="none")), FakeProvider())
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(tmp_path / "server.crt", tmp_path / "server.key")
    server = LocalServer(0, handler_for(broker), tls)
    (tmp_path / "server.json").write_text(json.dumps({"port": server.server_port}))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    path = tmp_path / "client.json"
    write_private(path, {"url": f"https://127.0.0.1:{server.server_port}/v1", "token": token,
                         "certificate": (tmp_path / "server.crt").read_text()})
    idle = socket.create_connection(("127.0.0.1", server.server_port))  # never sends a ClientHello
    try:
        runs = [threading.Thread(target=call_client, args=(path, {"operation": "run", "action": "test"}))
                for _ in range(2)]
        began = time.monotonic()
        for run in runs:
            run.start()
        time.sleep(0.5)
        start = time.monotonic()
        assert online(tmp_path)
        assert call_client(path, {"operation": "list"})["actions"][0]["name"] == "test"
        assert time.monotonic() - start < 2
        for run in runs:
            run.join(timeout=15)
        statuses = [json.loads(line)["status"] for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
        # Two 3-second actions overlap instead of queueing behind each other.
        assert statuses == ["started", "started", "completed", "completed"]
        assert time.monotonic() - began < 5.5
    finally:
        idle.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def write_policy(state, actions):
    # Distinct mtimes make each edit observable even on coarse filesystem clocks.
    path = state / "policy.json"
    previous = path.stat().st_mtime_ns if path.exists() else 0
    path.write_text(json.dumps({"version": 1, "actions": actions}))
    os.utime(path, ns=(previous + 10**9, previous + 10**9))


def grant(state, actions):
    (state / "clients.json").write_text(json.dumps({"agent": {"sha256": "unused", "actions": actions}}))


def hot_broker(tmp_path):
    grant(tmp_path, ["a", "b"])
    write_policy(tmp_path, {"a": command(tmp_path, "print('a1')"), "b": command(tmp_path, "print('b1')")})
    broker = Broker(tmp_path, policy(command(tmp_path, "print('ignored')")), FakeProvider())
    return broker, {"a", "b"}


def run(broker, allowed, name):
    return broker.invoke("agent", allowed, {"operation": "run", "action": name})["result"]["output"].strip()


def test_policy_edits_apply_without_restart(tmp_path):
    from keeper_agent.desktop import policy_digest
    broker, allowed = hot_broker(tmp_path)
    assert run(broker, allowed, "a") == "a1"
    write_policy(tmp_path, {"b": command(tmp_path, "print('b2')")})
    with pytest.raises(Denied, match="not permitted"):
        run(broker, allowed, "a")
    assert run(broker, allowed, "b") == "b2"
    assert [x["name"] for x in broker.invoke("agent", allowed, {"operation": "list"})["actions"]] == ["b"]
    status = json.loads((tmp_path / "broker-status.json").read_text())
    assert status["policyDigest"] == policy_digest(json.loads((tmp_path / "policy.json").read_text()))


def test_invalid_or_missing_policy_fails_closed(tmp_path):
    broker, allowed = hot_broker(tmp_path)
    assert run(broker, allowed, "a") == "a1"
    (tmp_path / "policy.json").write_text("{not json")
    for body in ({"operation": "run", "action": "a"}, {"operation": "list"}):
        with pytest.raises(Denied, match="policy is invalid"):
            broker.invoke("agent", allowed, body)
    assert json.loads((tmp_path / "broker-status.json").read_text())["policyDigest"] is None
    (tmp_path / "policy.json").unlink()
    with pytest.raises(Denied, match="policy is invalid"):
        run(broker, allowed, "a")
    write_policy(tmp_path, {"a": command(tmp_path, "print('a3')")})
    assert run(broker, allowed, "a") == "a3"


def test_queued_run_uses_the_policy_current_when_it_starts(tmp_path):
    broker, allowed = hot_broker(tmp_path)
    results = []
    for _ in range(Broker.concurrency):
        broker.slots.acquire()
    waiting = threading.Thread(target=lambda: results.append(run(broker, allowed, "a")))
    waiting.start()
    write_policy(tmp_path, {"a": command(tmp_path, "print('a2')")})
    for _ in range(Broker.concurrency):
        broker.slots.release()
    waiting.join(timeout=15)
    assert results == ["a2"]


def test_in_memory_policy_is_not_replaced_without_a_file(tmp_path):
    broker = Broker(tmp_path, policy(command(tmp_path, "print('memory')")), FakeProvider())
    grant(tmp_path, ["test"])
    assert run(broker, {"test"}, "test") == "memory"
    assert not (tmp_path / "broker-status.json").exists()


def test_revoking_a_client_stops_its_queued_runs(tmp_path):
    broker, allowed = hot_broker(tmp_path)
    errors = []
    def attempt():
        try:
            run(broker, allowed, "a")
        except Denied as error:
            errors.append(str(error))
    for _ in range(Broker.concurrency):
        broker.slots.acquire()
    waiting = threading.Thread(target=attempt)
    waiting.start()
    grant(tmp_path, [])
    for _ in range(Broker.concurrency):
        broker.slots.release()
    waiting.join(timeout=15)
    assert errors == ["Action not permitted"]
    assert not (tmp_path / "audit.jsonl").exists()


def test_actions_overlap_up_to_the_cap_while_vault_reads_stay_serial(tmp_path):
    import time
    lock = threading.Lock()
    counts = {"vault": 0, "vault_max": 0, "running": 0, "running_max": 0}

    def track(key, step):
        with lock:
            counts[key] += step
            counts[key + "_max"] = max(counts[key + "_max"], counts[key])

    class SlowVault(FakeProvider):
        def get(self, ref):
            track("vault", 1)
            time.sleep(0.05)
            track("vault", -1)
            return SECRET

    broker = Broker(tmp_path, policy(command(tmp_path, "print(1)")), SlowVault())
    grant(tmp_path, ["test"])
    execute = broker.engine.execute

    def slow_execute(*args):
        track("running", 1)
        time.sleep(0.4)
        track("running", -1)
        return execute(*args)

    broker.engine.execute = slow_execute
    runs = [threading.Thread(target=run, args=(broker, {"test"}, "test")) for _ in range(Broker.concurrency + 2)]
    for thread in runs:
        thread.start()
    for thread in runs:
        thread.join(timeout=20)
    assert counts["vault_max"] == 1
    assert counts["running_max"] == Broker.concurrency
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert len(lines) == 2 * (Broker.concurrency + 2) and all(json.loads(line) for line in lines)
