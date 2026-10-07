"""Exercise a packaged helper without contacting Keeper or any external service."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument("core", type=Path)
args = parser.parse_args()
core = args.core.resolve()
root = Path(__file__).resolve().parents[2]
(root / "work").mkdir(exist_ok=True)
state = Path(tempfile.mkdtemp(prefix="packaged-smoke-", dir=root / "work")) / "broker"


def request(operation, **payload):
    result = subprocess.run([str(core)], input=json.dumps({"operation": operation,
        "state": str(state), **payload}), text=True, capture_output=True, timeout=30)
    response = json.loads(result.stdout)
    assert result.returncode == 0 and response["ok"], response.get("error", "Helper failed")
    return response["data"]


started = time.perf_counter()
assert not request("snapshot")["initialized"]
first = time.perf_counter() - started
assert request("initialize", email="fixture@example.invalid", region="US")["initialized"]
action = {"kind": "http", "url": "https://example.invalid", "outputs": {}}
assert request("save_action", name="fixture", action=action)["actions"][0]["name"] == "fixture"
grant = request("create_client", name="fixture-agent", actions=["fixture"])
client = Path(grant["path"])
token = json.loads(client.read_text())["token"]
started = time.perf_counter()
snapshot = request("snapshot")
warm = time.perf_counter() - started
assert token not in json.dumps(snapshot)
assert snapshot["clients"][0]["actions"] == ["fixture"]
request("revoke_client", name="fixture-agent")
assert not client.exists()
assert not request("delete_action", name="fixture")["actions"]
help_result = subprocess.run([str(core), "serve", "--help"], capture_output=True, timeout=30)
assert help_result.returncode == 0
assert subprocess.run([str(core), "web", "--help"], capture_output=True, timeout=30).returncode == 0
print(json.dumps({"passed": True, "initialSnapshotSeconds": round(first, 3),
    "repeatSnapshotSeconds": round(warm, 3), "syntheticState": str(state)}))
