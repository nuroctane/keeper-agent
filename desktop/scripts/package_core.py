"""Build a directory-based Python helper: no runtime extraction on every action."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
subprocess.run([
    sys.executable, "-m", "PyInstaller", "--noconfirm", "--onedir",
    "--name", "keeper-agent-core", "--paths", str(root),
    "--distpath", str(root / "work" / "sidecar"),
    "--workpath", str(root / "work" / "pyinstaller"),
    "--specpath", str(root / "work"),
    "--collect-submodules", "keepercommander",
    "--collect-data", "keepercommander",
    "--collect-all", "playwright",
    str(Path(__file__).with_name("core_entry.py"))
], check=True, cwd=root)
print("Broker helper prepared. Build Tauri with --config src-tauri/tauri.bundle.conf.json")
