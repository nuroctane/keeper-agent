import io
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock
import subprocess

from keeper_agent.audit import AuditLog, files, verify
from keeper_agent.cli import main as cli_main


def fill(state, count, limit=10**9):
    log = AuditLog(state, limit=limit)
    for index in range(count):
        log.append({"id": str(index), "status": "started"})
    return log


def lines(path):
    return path.read_bytes().splitlines(keepends=True)


def test_chain_is_intact_and_survives_restart(tmp_path):
    fill(tmp_path, 5)
    fill(tmp_path, 3)  # a new broker process continues the same chain
    assert verify(tmp_path) == (8, None)


def test_rotation_keeps_one_chain_across_files(tmp_path):
    fill(tmp_path, 40, limit=600)
    assert len(files(tmp_path)) > 3
    assert verify(tmp_path) == (40, None)


def test_rotation_survives_a_clock_rollback_and_restart(tmp_path, monkeypatch):
    clock = {"now": datetime(2026, 10, 29, tzinfo=timezone.utc)}

    class Clock(datetime):
        @staticmethod
        def now(tz):
            return clock["now"]

    monkeypatch.setattr("keeper_agent.audit.datetime", Clock)
    log = AuditLog(tmp_path, limit=1)
    log.append({"id": "first"})
    log.append({"id": "second"})
    clock["now"] -= timedelta(hours=1)
    log.append({"id": "third"})
    assert verify(tmp_path) == (3, None)
    # Restarts must recover the ordering without relying on an in-memory clock.
    log = AuditLog(tmp_path, limit=1)
    log.append({"id": "fourth"})
    assert verify(tmp_path) == (4, None)
    # The latest entry may be in a rotated file if the process stops mid-rotation.
    (tmp_path / "audit.jsonl").replace(tmp_path / "audit-20261029T000000000003Z-last.jsonl")
    fill(tmp_path, 1, limit=1)
    assert verify(tmp_path) == (5, None)


def test_editing_an_entry_breaks_the_chain(tmp_path):
    fill(tmp_path, 5)
    path = tmp_path / "audit.jsonl"
    rows = lines(path)
    rows[2] = rows[2].replace(b'"started"', b'"completed"')
    path.write_bytes(b"".join(rows))
    count, problem = verify(tmp_path)
    assert count == 3 and "line 4 does not follow" in problem


def test_removing_an_entry_or_a_rotated_file_breaks_the_chain(tmp_path):
    fill(tmp_path, 5)
    path = tmp_path / "audit.jsonl"
    rows = lines(path)
    path.write_bytes(b"".join(rows[:1] + rows[2:]))
    assert verify(tmp_path)[1] is not None

    other = tmp_path / "rotated"
    other.mkdir()
    fill(other, 40, limit=600)
    files(other)[1].unlink()
    assert "does not follow" in verify(other)[1]
    files(other)[0].unlink()
    assert "does not follow" in verify(other)[1]


def test_entries_from_before_chaining_may_only_precede_it(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text(json.dumps({"id": "legacy", "status": "started"}) + "\n")
    fill(tmp_path, 3)
    assert verify(tmp_path) == (4, None)
    with path.open("a") as stream:
        stream.write(json.dumps({"id": "inserted", "status": "completed"}) + "\n")
    assert "missing its chain link" in verify(tmp_path)[1]


def test_concurrent_writers_keep_the_chain_intact(tmp_path):
    log = AuditLog(tmp_path, limit=4000)
    threads = [threading.Thread(target=lambda n=n: [log.append({"id": f"{n}-{i}"}) for i in range(25)])
               for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert verify(tmp_path) == (200, None)


def test_audit_verify_command_reports_and_exits(tmp_path, capsys):
    fill(tmp_path, 3)
    assert cli_main(["audit-verify", "--state", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["intact"] is True
    (tmp_path / "audit.jsonl").write_bytes(b"not json\n")
    assert cli_main(["audit-verify", "--state", str(tmp_path)]) == 1
    assert json.loads(capsys.readouterr().out)["intact"] is False


def test_broker_writes_a_verifiable_chain(tmp_path):
    from keeper_agent.server import Broker
    from tests.test_broker import FakeProvider, command, grant, policy
    broker = Broker(tmp_path, policy(command(tmp_path, "print(1)")), FakeProvider())
    grant(tmp_path, ["test"])
    for _ in range(3):
        broker.invoke("agent", {"test"}, {"operation": "run", "action": "test"})
    assert verify(tmp_path) == (6, None)


def test_worker_stops_serving_when_its_parent_goes_away():
    from keeper_agent.web_worker import watch_parent
    stop = threading.Event()
    watch_parent(io.StringIO(""), stop)
    assert stop.is_set()


def test_serve_stops_on_request_logs_out_and_clears_status(tmp_path):
    from keeper_agent.cli import certificate
    from keeper_agent.security import write_private
    from keeper_agent.server import serve
    from tests.test_broker import FakeProvider, command, policy
    certificate(tmp_path)
    write_private(tmp_path / "server.json", {"port": 0})
    provider = FakeProvider()
    provider.close = Mock()
    stop = threading.Event()
    seen = []

    def ready():
        seen.append((tmp_path / "broker-status.json").exists())
        stop.set()
        # Give the stop watcher a chance to run before the serving loop starts.
        # The old serve_forever/shutdown combination could lose that signal.
        time.sleep(0.1)

    thread = threading.Thread(target=serve, args=(tmp_path, policy(command(tmp_path, "print(1)")), provider),
                              kwargs={"ready": ready, "stop": stop}, daemon=True)
    thread.start()
    thread.join(timeout=15)
    assert not thread.is_alive()
    assert seen == [True]
    provider.close.assert_called_once()
    assert not (tmp_path / "broker-status.json").exists()


def test_disconnect_lets_the_worker_exit_before_forcing_it(monkeypatch):
    from keeper_agent.web import Worker
    process_lookup = Mock()
    monkeypatch.setattr('psutil.Process', process_lookup)
    graceful = Mock()
    graceful.poll.return_value = 0
    worker = Worker()
    worker.process = graceful
    worker.stop()
    graceful.stdin.close.assert_called_once()
    graceful.wait.assert_called_once_with(timeout=5)
    process_lookup.assert_not_called()

    stuck = Mock()
    stuck.wait.side_effect = subprocess.TimeoutExpired("worker", 5)
    stuck.poll.return_value = None
    process_lookup.return_value.children.return_value = []
    monkeypatch.setattr('psutil.wait_procs', Mock(return_value=([], [])))
    worker.process = stuck
    worker.stop()
    process_lookup.return_value.terminate.assert_called_once()


def test_rotation_blocked_by_a_reader_retries_later(tmp_path, monkeypatch):
    from pathlib import Path
    real_replace = Path.replace
    blocked = {"left": 1}

    def replace(self, target):
        if blocked["left"]:
            blocked["left"] -= 1
            raise PermissionError("file in use")
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", replace)
    fill(tmp_path, 30, limit=600)
    assert blocked["left"] == 0 and len(files(tmp_path)) > 1
    assert verify(tmp_path) == (30, None)
