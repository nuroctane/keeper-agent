"""Archive the standalone runtime with its browser setup guide."""
from pathlib import Path
import shutil
import zipfile

root = Path(__file__).resolve().parents[2]
archive = shutil.make_archive(str(root / 'work' / 'keeper-agent-web'), 'zip',
                              root / 'work' / 'sidecar', 'keeper-agent-core')
with zipfile.ZipFile(archive, 'a', compression=zipfile.ZIP_DEFLATED) as package:
    package.write(root / 'docs' / 'WEB.md', 'START-HERE.md')
    package.write(root / 'README.md', 'SECURITY-AND-CLI.md')
print(archive)
