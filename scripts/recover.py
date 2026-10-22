#!/usr/bin/env python3
"""Offline-first recovery staging. This program never signs or launches clients."""
import argparse
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
from reconcile import reconcile

BASE = Path(__file__).resolve().parent.parent
HASH = re.compile(r"^[a-f0-9]{64}$")
# The observed production snapshot contains over 169,000 files plus directory
# and symlink metadata. Bound its JSON inventory independently of payload size.
MAX_MANIFEST_BYTES = 256 * 1024 * 1024
REQUIRED = (
    "var/lib/wdi-acurast-manager/vault/key.json",
    "var/lib/wdi-acurast-manager/vault/registry.json",
    "var/lib/wdi-acurast-manager/transfer-private.pem",
    "var/lib/wdi-acurast-manager/workers.json",
    "var/lib/wdi-acurast-native/operator_ed25519",
    "var/lib/wdi-acurast-telemetry/deployments.json",
)


class RecoveryError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise RecoveryError(message)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative(name):
    require(isinstance(name, str), "Relative path must be text")
    p = PurePosixPath(name)
    require(name and not p.is_absolute() and
            ".." not in p.parts and "\\" not in name and str(p) == name,
            "Unsafe or noncanonical relative path")
    return p


def private_dir(path):
    path = Path(path).absolute()
    for parent in [*reversed(path.parents), path]:
        if parent.exists():
            require(not parent.is_symlink(), "Symlink in recovery directory path")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(path.is_dir(), "Recovery destination is not a directory")
    path.chmod(0o700)
    return path


def write_json(path, value):
    path = Path(path)
    private_dir(path.parent)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".write-")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def command(args, label, stdout=None):
    result = subprocess.run(args, stdout=stdout or subprocess.PIPE, stderr=subprocess.PIPE)
    require(result.returncode == 0, label + " failed; private subprocess output suppressed")
    return result.stdout if stdout is None else None


def read_manifest(path):
    m = json.loads(Path(path).read_text())
    require(m.get("schema") == 2, "Unsupported release manifest schema; use the private plaintext artifact manifest")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/Accurast", m.get("repository", "")), "Unexpected repository")
    require(isinstance(m.get("tag"), str) and m["tag"] and not m["tag"].startswith("-"), "Invalid release tag")
    require(isinstance(m.get("artifacts"), list) and m["artifacts"], "No release artifacts configured")
    names, destinations = set(), set()
    for artifact in m["artifacts"]:
        name = artifact["name"]
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]+", name), "Invalid asset name")
        require(name not in names, "Duplicate asset name")
        names.add(name)
        require(artifact["kind"] in ("snapshot", "local-state", "immutable"), "Unknown artifact kind")
        require(HASH.fullmatch(artifact["sha256"]), "Invalid asset hash")
        require(isinstance(artifact["bytes"], int) and artifact["bytes"] > 0, "Invalid asset length")
        relative(artifact["destination"])
        require(not any(artifact["destination"] == old or artifact["destination"].startswith(old + "/") or old.startswith(artifact["destination"] + "/") for old in destinations), "Overlapping artifact destination")
        destinations.add(artifact["destination"])
    require(sum(a["kind"] == "snapshot" for a in m["artifacts"]) == 1, "Exactly one authoritative host snapshot required")
    return m


def preflight(manifest, online=True):
    needed = ["node"] + (["gh"] if online else [])
    require(all(shutil.which(name) for name in needed), "Install documented dependencies: " + ", ".join(needed))
    if online:
        raw = command(["gh", "api", "repos/" + manifest["repository"]], "GitHub repository verification")
        repo = json.loads(raw)
        require(repo.get("private") is True and repo.get("full_name", "").lower() == manifest["repository"].lower(), "Repository is not the expected PRIVATE repository")
    return {"ok": True, "checked_utc": utc(), "repository_private_checked": online,
            "python": sys.version.split()[0], "mode": "isolated-no-launch-no-signing"}


def verify_archive(archive, extract_to=None):
    """All regular members have a manifest digest; never call tar.extractall."""
    with tarfile.open(archive, "r:*") as tar:
        members = tar.getmembers()
        names = set()
        for member in members:
            relative(member.name.rstrip("/") if member.isdir() else member.name)
            require(member.name not in names, "Duplicate archive member")
            names.add(member.name)
            require(member.isfile() or member.isdir(), "Archive links/devices are forbidden")
            require(not member.mode & 0o7000, "Special archive permission bits forbidden")
        require("manifest.json" in names, "Archive lacks manifest.json")
        require(0 < tar.getmember("manifest.json").size <= MAX_MANIFEST_BYTES, "Oversized or empty file manifest (maximum 256 MiB)")
        manifest = json.load(tar.extractfile("manifest.json"))
        expected = manifest["files"]
        require(isinstance(expected, dict), "Invalid archive file manifest")
        require("manifest.json" not in expected, "Self-referential file manifest")
        require({m.name for m in members if m.isfile()} == set(expected) | {"manifest.json"}, "Archive manifest coverage mismatch")
        # Read in archive order: gzip random seeks can repeatedly decompress GBs.
        for member in members:
            if not member.isfile() or member.name == "manifest.json":
                continue
            name, record = member.name, expected[member.name]
            relative(name)
            require(HASH.fullmatch(record["sha256"]), "Invalid member digest")
            require(member.isfile() and member.size == record["bytes"], "Archive member size mismatch")
            h = hashlib.sha256()
            with tar.extractfile(member) as stream:
                for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
                    h.update(chunk)
            require(h.hexdigest() == record["sha256"], "Archive member hash mismatch")
        if extract_to is not None:
            dest = private_dir(extract_to)
            require(not any(dest.iterdir()), "Extraction target must be empty")
            for member in members:
                target = dest.joinpath(*PurePosixPath(member.name).parts)
                if member.isdir():
                    private_dir(target)
                    continue
                private_dir(target.parent)
                with tar.extractfile(member) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, 4 * 1024 * 1024)
                target.chmod(0o600)  # staged content is data, never executable
            write_json(dest / ".isolation.json", {"created_utc": utc(), "live_root": False,
                       "services_started": 0, "transactions_signed": 0})
        return manifest


def verify_tree(root, manifest):
    root = Path(root).absolute()
    private_dir(root)
    for name, rec in manifest["files"].items():
        p = root.joinpath(*relative(name).parts)
        require(all(not parent.is_symlink() for parent in p.parents if parent != root and root in parent.parents), "Symlinked restored parent")
        require(p.is_file() and not p.is_symlink(), "Restored file missing or symlinked")
        require(p.stat().st_size == rec["bytes"] and sha(p) == rec["sha256"], "Restored file digest mismatch")
    return len(manifest["files"])


def snapshot_file(root, name, manifest=None):
    """Resolve captured symlink metadata without creating or following host links."""
    root = Path(root).absolute()
    relative(name)
    manifest = manifest or json.loads((root / "manifest.json").read_text())
    links = manifest.get("symlinks", {})
    pending, resolved, hops = list(PurePosixPath(name).parts), [], 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            require(resolved, "Captured symlink escapes snapshot root")
            resolved.pop()
            continue
        current = "/".join(resolved + [part])
        if current in links:
            hops += 1
            require(hops <= 40, "Captured symlink loop or excessive depth")
            target = links[current]["target"]
            require(isinstance(target, str) and target and "\\" not in target and "\x00" not in target,
                    "Invalid captured symlink target")
            if target.startswith("/"):
                resolved = []
            pending = target.split("/") + pending
        else:
            resolved.append(part)
    final_name = "/".join(resolved)
    require(final_name in manifest["files"], "Captured link target was not preserved")
    path = root.joinpath(*resolved)
    require(path.is_file() and not path.is_symlink(), "Captured target is missing or a physical symlink")
    require(all(not p.is_symlink() for p in path.parents if p == root or root in p.parents),
            "Captured target parent is a physical symlink")
    record = manifest["files"][final_name]
    require(path.stat().st_size == record["bytes"] and sha(path) == record["sha256"], "Captured target digest mismatch")
    return path


def verify_sqlite(root, manifest):
    checked = 0
    for name in manifest["files"]:
        p = root / name
        if p.stat().st_size < 16:
            continue
        with p.open("rb") as stream:
            is_db = stream.read(16) == b"SQLite format 3\x00"
        if not is_db:
            continue
        # immutable mode avoids creating journals alongside private snapshots.
        with contextlib.closing(sqlite3.connect(p.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)) as conn:
            rows = conn.execute("PRAGMA integrity_check").fetchall()
            require(rows == [("ok",)], "Restored SQLite integrity check failed")
        checked += 1
    return checked


def verify_host(root, manifest):
    require(all((root / p).is_file() for p in REQUIRED), "Required authority/identity state absent")
    raw = command(["node", str(BASE / "scripts/verify-vault.mjs"), str(root)], "Vault/profile consistency verification")
    vault = json.loads(raw)
    require(vault.get("ok") is True, "Vault validation did not succeed")
    pawns_raw = command(["node", str(BASE / "scripts/verify-pawns.mjs"), str(root)], "Pawns native session/key consistency verification")
    pawns = json.loads(pawns_raw)
    require(pawns.get("ok") is True, "Pawns native session validation did not succeed")
    sqlite_count = verify_sqlite(root, manifest)
    return {"vault": vault, "pawns": pawns, "sqlite_databases_verified": sqlite_count,
            "required_files_verified": len(REQUIRED)}


def download_asset(manifest, artifact, cache, offline):
    path = cache / artifact["name"]
    if path.exists():
        require(not path.is_symlink(), "Symlink in asset cache")
        if path.stat().st_size == artifact["bytes"] and sha(path) == artifact["sha256"]:
            return path
        raise RecoveryError("Existing asset failed verification; move it aside before resuming")
    require(not offline, "Asset missing from offline cache")
    # A private scratch directory prevents partially downloaded bytes being adopted.
    with tempfile.TemporaryDirectory(dir=cache, prefix="download-") as temp:
        command(["gh", "release", "download", manifest["tag"], "--repo", manifest["repository"],
                 "--pattern", artifact["name"], "--dir", temp], "Release asset download")
        downloaded = Path(temp) / artifact["name"]
        require(downloaded.is_file() and downloaded.stat().st_size == artifact["bytes"] and sha(downloaded) == artifact["sha256"], "Remote asset digest mismatch")
        downloaded.chmod(0o600)
        os.replace(downloaded, path)
    return path


def restore(args, manifest):
    preflight(manifest, online=not args.offline)
    work = private_dir(args.work)
    require(work != Path("/"), "Live root is forbidden")
    cache, roots = private_dir(work / "asset-cache"), private_dir(work / "restored")
    report = {"schema": 2, "started_utc": utc(), "repository": manifest["repository"],
              "tag": manifest["tag"], "release_manifest_sha256": sha(args.manifest),
              "mode": "isolated-no-launch-no-signing", "artifacts": [],
              "outer_backup_encryption": False, "separate_recovery_key_required": False,
              "live_provisioning_tested": False, "services_started": 0, "transactions_signed": 0}
    with (work / "recovery.lock").open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RecoveryError("Another recovery process owns this work directory")
        for artifact in manifest["artifacts"]:
            archive = download_asset(manifest, artifact, cache, args.offline)
            dest = roots.joinpath(*relative(artifact["destination"]).parts)
            proof_path = work / ("proof-" + artifact["name"] + ".json")
            if dest.exists():
                require(proof_path.is_file(), "Unverified restore destination exists; move it aside before resuming")
                proof = json.loads(proof_path.read_text())
                require(proof["sha256"] == artifact["sha256"], "Restore proof belongs to another artifact")
                if artifact["kind"] == "immutable":
                    require(dest.is_file() and not dest.is_symlink() and sha(dest) == artifact["sha256"], "Restored immutable asset digest mismatch")
                    entry = {"name": artifact["name"], "kind": artifact["kind"], "verified": True}
                else:
                    member_manifest = json.loads((dest / "manifest.json").read_text())
                    require(sha(dest / "manifest.json") == proof["member_manifest_sha256"], "Restored manifest changed")
                    count = verify_tree(dest, member_manifest)
                    entry = {"name": artifact["name"], "kind": artifact["kind"], "files_verified": count}
                    if artifact["kind"] == "snapshot":
                        entry.update(verify_host(dest, member_manifest))
                entry["resumed"] = True
                report["artifacts"].append(entry)
                continue
            private_dir(dest.parent)
            with tempfile.TemporaryDirectory(dir=work, prefix="extract-") as temp:
                proof = {"sha256": artifact["sha256"], "verified_utc": utc()}
                if artifact["kind"] == "immutable":
                    shutil.copyfile(archive, dest)
                    dest.chmod(0o600)
                    require(sha(dest) == artifact["sha256"], "Restored immutable asset digest mismatch")
                    entry = {"name": artifact["name"], "kind": artifact["kind"], "verified": True}
                else:
                    staged = Path(temp) / "tree"
                    member_manifest = verify_archive(archive, staged)
                    count = verify_tree(staged, member_manifest)
                    entry = {"name": artifact["name"], "kind": artifact["kind"], "files_verified": count}
                    if artifact["kind"] == "snapshot":
                        entry.update(verify_host(staged, member_manifest))
                    proof["member_manifest_sha256"] = sha(staged / "manifest.json")
                    os.replace(staged, dest)
                write_json(proof_path, proof)
            report["artifacts"].append(entry)
        snapshot_hash = next(a["sha256"] for a in manifest["artifacts"] if a["kind"] == "snapshot")
        if args.evidence:
            evidence_path = Path(args.evidence)
            evidence = json.loads(evidence_path.read_text())
            require(isinstance(evidence, dict) and evidence.get("source_snapshot_sha256") == snapshot_hash,
                    "Reconciliation evidence does not match the selected snapshot hash")
            try:
                plan = reconcile(evidence)
            except (KeyError, TypeError, ValueError):
                raise RecoveryError("Malformed reconciliation evidence; all live actions remain held")
            plan.update(status="fresh-evidence-plan-created", source_snapshot_sha256=snapshot_hash,
                        evidence_sha256=sha(evidence_path), fresh_evidence_supplied=True)
        else:
            plan = {"schema": 1, "status": "not-reconciled-no-fresh-evidence",
                    "source_snapshot_sha256": snapshot_hash, "fresh_evidence_supplied": False,
                    "live_actions_allowed": False, "blockers": ["fresh-chain-process-and-transaction-evidence-required"],
                    "jobs": [], "transactions": [], "note": "Restored historical journals are preserved, not replayed. Fresh live reconciliation has not been performed."}
        require(plan.get("live_actions_allowed") is False, "Recovery reconciliation cannot enable live actions")
        plan_path = work / "reconciliation-plan.json"
        write_json(plan_path, plan)
        report["reconciliation"] = {"status": plan["status"], "plan_file": plan_path.name,
                                    "plan_sha256": sha(plan_path), "source_snapshot_sha256": snapshot_hash,
                                    "fresh_evidence_supplied": plan["fresh_evidence_supplied"],
                                    "blockers": plan["blockers"], "live_actions_allowed": False}
        report.update(ok=True, completed_utc=utc())
        write_json(work / "restore-verification.json", report)
    print(json.dumps(report, indent=2))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["restore", "preflight", "verify-archive"])
    parser.add_argument("--manifest", default=str(BASE / "release-assets.json"))
    parser.add_argument("--work", default=str(BASE / ".recovery"))
    parser.add_argument("--offline", action="store_true", help="Use already verified asset-cache files; does not prove remote access")
    parser.add_argument("--archive", help="For verify-archive only")
    parser.add_argument("--evidence", help="Optional fresh reconciliation evidence bound to the selected snapshot SHA256; never enables launches")
    args = parser.parse_args()
    if args.action == "verify-archive":
        require(args.archive, "--archive required")
        result = verify_archive(args.archive)
        print(json.dumps({"ok": True, "files_verified": len(result["files"])}))
        return
    manifest = read_manifest(args.manifest)
    if args.action == "preflight":
        print(json.dumps(preflight(manifest, not args.offline), indent=2))
    else:
        restore(args, manifest)


if __name__ == "__main__":
    try:
        main()
    except (RecoveryError, OSError, ValueError, KeyError, tarfile.TarError, sqlite3.Error) as error:
        # Suppress arbitrary raw file/library error values: they can contain private data.
        reason = str(error) if isinstance(error, RecoveryError) else type(error).__name__
        print(json.dumps({"ok": False, "error": reason}), file=sys.stderr)
        sys.exit(1)
