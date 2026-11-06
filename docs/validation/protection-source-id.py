"""Fingerprint the checked-out enforcement, test and deployment inputs, including unpublished files."""

import hashlib
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[2]
paths = [
    ".github", "apps", "deployment", "evals", "examples", "integrations", "packages",
    "schemas", "scripts", "tools", ".gitattributes", ".npmrc", "package.json", "package-lock.json", "tsconfig.base.json",
]
files = subprocess.check_output(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", *paths],
    cwd=root,
).split(b"\0")
digest = hashlib.sha256()
count = 0
for name in sorted(set(filter(None, files))):
    path = root / name.decode("utf-8")
    if path.is_symlink():
        raise SystemExit("Unexpected symbolic link in reviewed inputs")
    if path.exists():
        digest.update(name + b"\0" + hashlib.sha256(path.read_bytes()).digest())
        count += 1
print(f"{digest.hexdigest()}  ({count} files)")
