"""Build a directory-based Python helper: no runtime extraction on every action."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
assets = root / "desktop" / "dist"
if not (assets / "index.html").is_file():
    raise SystemExit("Build the shared interface first: cd desktop && npm run build")
subprocess.run([
    sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm", "--onedir",
    "--name", "keeper-agent-core", "--paths", str(root),
    "--distpath", str(root / "work" / "sidecar"),
    "--workpath", str(root / "work" / "pyinstaller"),
    "--specpath", str(root / "work"),
    "--collect-submodules", "keepercommander",
    "--collect-data", "keepercommander",
    "--collect-all", "playwright",
    "--add-data", f"{assets}:web_assets",
    str(Path(__file__).with_name("core_entry.py"))
], check=True, cwd=root)
print("Broker helper prepared. Build Tauri with --config src-tauri/tauri.bundle.conf.json")
