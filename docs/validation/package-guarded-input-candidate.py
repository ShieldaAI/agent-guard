"""Stage two local packs of checked build outputs and exercise their installed public entry points."""

import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WORKSPACES = ("core", "mcp", "scenarios", "executor", "agent-map")
VIEWER = "agent-map-guarded-input-viewer.tar.gz"
MANIFEST = "guarded-input-manifest.json"
COMBINED = "agent-guard-guarded-input-candidate.tar.gz"
OFFLINE = {**os.environ, "npm_config_offline": "true", "npm_config_audit": "false",
           "npm_config_fund": "false", "npm_config_update_notifier": "false"}


def run(args, cwd):
    return subprocess.check_output(args, cwd=cwd, env=OFFLINE, text=True).strip()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path, algorithm="sha256"):
    return hashlib.new(algorithm, path.read_bytes())


def encoded(value):
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode()


def source_id():
    result = run([sys.executable, str(HERE / "protection-source-id.py")], ROOT)
    digest, files = result.split("  ")
    require(re.fullmatch(r"[a-f0-9]{64}", digest) and re.fullmatch(r"\([0-9]+ files\)", files), "Unexpected fingerprint")
    return digest


def archive(target, sources):
    # No host mtimes, mode variations, path prefixes, uid/gid or gzip filename.
    with target.open("xb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as zipped:
        with tarfile.open(mode="w|", fileobj=zipped, format=tarfile.USTAR_FORMAT) as bundle:
            for source in sorted(sources, key=lambda p: p.name):
                require(source.is_file() and not source.is_symlink(), "Unexpected archive member")
                member = tarfile.TarInfo(source.name)
                member.size = source.stat().st_size
                member.mode = 0o644
                with source.open("rb") as content:
                    bundle.addfile(member, content)


def record(name, path):
    return {"name": name, "file": path.name, "bytes": path.stat().st_size, "sha256": sha(path).hexdigest()}


def package(stage, source):
    stage.mkdir()
    entries = []
    for leaf in WORKSPACES:
        workspace = ROOT / "packages" / leaf
        metadata = json.loads((workspace / "package.json").read_text())
        result, = json.loads(run(["npm", "pack", "--offline", "--ignore-scripts", "--json",
                                  "--pack-destination", str(stage)], workspace))
        path = stage / result["filename"]
        require(path.parent == stage and result["name"] == metadata["name"] and
                result["version"] == metadata["version"], "Unexpected npm package")
        entry = record(metadata["name"], path)
        entry["version"] = metadata["version"]
        entry["npmIntegrity"] = "sha512-" + base64.b64encode(sha(path, "sha512").digest()).decode()
        require(result["integrity"] == entry["npmIntegrity"], "npm integrity mismatch")
        entries.append(entry)

    viewer = ROOT / "apps" / "agent-map" / "dist"
    assets = list(viewer.iterdir())
    require({p.name for p in assets} == {"app.js", "app.css", "index.html"}, "Unexpected viewer assets")
    archive(stage / VIEWER, assets)
    entries.append(record("private-reference-viewer", stage / VIEWER))
    manifest = {"kind": "unsigned-local-guarded-input-candidate", "sourceSha256": source, "artifacts": entries}
    (stage / MANIFEST).write_bytes(encoded(manifest))
    archive(stage / COMBINED, [stage / entry["file"] for entry in entries] + [stage / MANIFEST])
    return manifest


def normalized_entries(directory):
    return {p.name: sha(p).hexdigest() for p in directory.iterdir() if p.is_file() and not p.is_symlink()}


def consumer_qa(consumer, stage, manifest, image):
    # Install tarballs taken back out of the aggregate so the same command tests the distributed object.
    consumer.mkdir()
    tarballs = consumer / "tarballs"
    tarballs.mkdir()
    with tarfile.open(stage / COMBINED, "r:gz") as bundle:
        members = bundle.getmembers()
        require(sorted(m.name for m in members) == sorted([e["file"] for e in manifest["artifacts"]] + [MANIFEST]),
                "Unexpected combined archive members")
        for m in members:
            require(m.isfile() and m.name == Path(m.name).name, "Unsafe combined archive member")
            data = bundle.extractfile(m).read()
            require(data == (stage / m.name).read_bytes(), "Combined archive content mismatch")
            if m.name.endswith(".tgz"):
                (tarballs / m.name).write_bytes(data)
    packages = [e for e in manifest["artifacts"] if "npmIntegrity" in e]
    locked = json.loads((ROOT / "package-lock.json").read_text())["packages"]
    # npm can otherwise select a newer cached patch than the actual workspace lock.
    versions = {}
    allowed = set()
    for location, entry in locked.items():
        if "node_modules/" in location and "integrity" in entry:
            package_name = location.rsplit("node_modules/", 1)[1]
            versions.setdefault(package_name, set()).add(entry["version"])
            allowed.add((package_name, entry["version"], entry["integrity"]))
    overrides = {name: next(iter(values)) for name, values in versions.items() if len(values) == 1}
    spec = {"name": "guarded-input-local-consumer", "version": "1.0.0", "private": True, "type": "module",
            "dependencies": {p["name"]: "file:tarballs/" + p["file"] for p in packages}, "overrides": overrides}
    (consumer / "package.json").write_bytes(encoded(spec))
    run(["npm", "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund"], consumer)
    installed = json.loads((consumer / "package-lock.json").read_text())["packages"]
    verified = {}
    for package in packages:
        location = "node_modules/" + package["name"]
        entry = installed[location]
        require(entry["integrity"] == package["npmIntegrity"] and not entry.get("link") and
                entry["version"] == package["version"], "Installed the wrong local package")
        verified[location] = entry["integrity"]
    for location, entry in installed.items():
        if location and location not in verified:
            package_name = location.rsplit("node_modules/", 1)[-1]
            require((package_name, entry["version"], entry["integrity"]) in allowed,
                    "Offline install selected a third-party dependency outside the workspace lock: " + location)
            verified[location] = entry["integrity"]
    probe = HERE / "guarded-input-consumer.mjs"
    fixture = ROOT / "packages" / "executor" / "test" / "fixtures" / "packed-build-attestation.json"
    for path in (probe, fixture):
        shutil.copyfile(path, consumer / path.name)
    observed = json.loads(run(["node", probe.name, image], consumer))
    return {"npm": run(["npm", "--version"], consumer), "offlineInstall": True,
            "verifiedLocalPackageIntegrities": len(packages), "verifiedThirdPartyIntegrities": len(verified) - len(packages),
            "installedIntegritySetSha256": hashlib.sha256(encoded(sorted(verified.items()))).hexdigest(),
            "probeSha256": sha(probe).hexdigest(), "observed": observed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-source", required=True, help="Hash reported after npm run check for this exact tree")
    parser.add_argument("--image", required=True, help="Digest-pinned, locally present Linux shell image")
    args = parser.parse_args()
    source = source_id()
    require(source == args.expected_source, "Source fingerprint differs from checked candidate")
    require(re.fullmatch(r"[A-Za-z0-9./:_-]+@sha256:[a-f0-9]{64}", args.image), "Expected a digest-pinned image")
    artifacts = ROOT / "artifacts"
    out = artifacts / ("guarded-input-candidate-" + source)
    report = HERE / ("guarded-input-candidate-" + source + ".json")
    with tempfile.TemporaryDirectory(dir=artifacts, prefix=".guarded-pack-") as batches:
        tmp = Path(batches)
        first, second = tmp / "first", tmp / "second"
        manifest = package(first, source)
        package(second, source)
        require(normalized_entries(first) == normalized_entries(second), "Two local pack runs differ")
        require(source_id() == source, "Source changed while packing")
        with tempfile.TemporaryDirectory(prefix="guarded-install-") as private:
            qa = consumer_qa(Path(private).resolve() / "consumer", first, manifest, args.image)
        require(source_id() == source, "Source changed during installed verification")
        public = {**manifest, "combined": record("combined-candidate", first / COMBINED),
                  "localDirectory": str(out.relative_to(ROOT)), "twoPacksByteIdentical": True,
                  "packagingToolSha256": sha(Path(__file__)).hexdigest(), "installedConsumer": qa}
        payload = encoded(public)
        if report.exists():
            require(report.read_bytes() == payload, "Existing public report differs; refusing to overwrite")
        if out.exists():
            require({p.name for p in out.iterdir()} == {p.name for p in first.iterdir()} and
                    normalized_entries(out) == normalized_entries(first), "Existing candidate differs; refusing to overwrite")
        else:
            first.rename(out)
        if not report.exists():
            with report.open("xb") as target:
                target.write(payload)
        print(json.dumps({"sourceSha256": source, "archiveSha256": public["combined"]["sha256"],
                          "bytes": public["combined"]["bytes"], "report": str(report.relative_to(ROOT))}))


if __name__ == "__main__":
    main()
