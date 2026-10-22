import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / "scripts"))
from recover import RecoveryError, download_asset, preflight, read_manifest, sha, verify_archive, verify_tree
from reconcile import reconcile
merge_spec = importlib.util.spec_from_file_location("merge_local", BASE / "scripts/merge-local-delta.py")
merge_module = importlib.util.module_from_spec(merge_spec)
merge_spec.loader.exec_module(merge_module)
prep_spec = importlib.util.spec_from_file_location("prepare_linux", BASE / "scripts/prepare-linux-root.py")
prep_module = importlib.util.module_from_spec(prep_spec)
prep_spec.loader.exec_module(prep_module)
audit_spec = importlib.util.spec_from_file_location("audit_migration", BASE / "scripts/audit-migration.py")
audit_module = importlib.util.module_from_spec(audit_spec)
audit_spec.loader.exec_module(audit_module)


def archive(path, files, extra=None):
    records = {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "source_mode": 0o600,
                     "source_uid": os.getuid(), "source_gid": os.getgid()} for name, data in files.items()}
    # Reverse manifest insertion order explicitly exercises gzip member-order reads.
    manifest = {"files": dict(reversed(list(records.items())))}
    with tarfile.open(path, "w:gz") as t:
        for name, data in sorted({**files, "manifest.json": json.dumps(manifest).encode()}.items()):
            m = tarfile.TarInfo(name); m.size = len(data); m.mode = 0o600
            t.addfile(m, io.BytesIO(data))
        if extra:
            extra(t)
    return manifest


class ArchiveSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name).resolve()
    def tearDown(self):
        self.tmp.cleanup()
    def test_exact_extract_and_tamper(self):
        tar = self.root / "state.tar.gz"
        manifest = archive(tar, {"nested/state": b"original-state", "other/file": b"receipt"})
        dest = self.root / "out"
        verify_archive(tar, dest)
        self.assertEqual(verify_tree(dest, manifest), 2)
        (dest / "nested/state").write_bytes(b"modified-state")
        with self.assertRaises(RecoveryError): verify_tree(dest, manifest)
    def test_reject_symlink(self):
        def link(t):
            m = tarfile.TarInfo("link"); m.type = tarfile.SYMTYPE; m.linkname = "/tmp/target"; t.addfile(m)
        tar = self.root / "state.tar.gz"; archive(tar, {"state": b"a"}, link)
        with self.assertRaises(RecoveryError): verify_archive(tar)
    def test_reject_traversal(self):
        tar = self.root / "state.tar.gz"; archive(tar, {"../escape": b"secret"})
        with self.assertRaises(RecoveryError): verify_archive(tar, self.root / "out")
        self.assertFalse((self.root / "escape").exists())
    def test_reject_duplicate_member(self):
        def duplicate(t):
            m = tarfile.TarInfo("state"); m.size = 1; t.addfile(m, io.BytesIO(b"b"))
        tar = self.root / "state.tar.gz"; archive(tar, {"state": b"a"}, duplicate)
        with self.assertRaises(RecoveryError): verify_archive(tar)
    def test_reject_parent_symlink_on_resume(self):
        tar = self.root / "state.tar.gz"; manifest = archive(tar, {"nested/state": b"a"})
        dest = self.root / "out"; verify_archive(tar, dest)
        (dest / "nested").rename(self.root / "elsewhere")
        (dest / "nested").symlink_to(self.root / "elsewhere")
        with self.assertRaises(RecoveryError): verify_tree(dest, manifest)


def evidence():
    return {"source_snapshot_sha256": "a" * 64, "chain_finalized_block": "0x1", "chain_observed_at": 990,
            "process_observed_at": 995, "authority_fenced": True, "journal_reconciled": True,
            "wallets": [{"role": "rental_wallet", "address": "synthetic", "free_pico": "1"}],
            "transactions": [{"hash": "0xtest", "status": "finalized-success"}],
            "jobs": [{"job_id": 123, "canonical_profile_hash": "b" * 64, "original_identity_matches": True,
                      "processor_matches": True, "expected_ip_matches": True, "lease_end": 1100,
                      "assignment": "active-acknowledged", "process": "running-matching-identity",
                      "observed_ip": "192.0.2.1"}]}


class ReconciliationSafety(unittest.TestCase):
    def test_running_client_is_adopt_candidate_never_launch(self):
        result = reconcile(evidence(), now=1000)
        self.assertEqual(result["jobs"][0]["decision"], "adopt-candidate-do-not-launch")
        self.assertFalse(result["live_actions_allowed"])
        self.assertFalse(result["jobs"][0]["launch_allowed"])
    def test_pending_transaction_blocks_everything(self):
        e = evidence(); e["transactions"][0]["status"] = "broadcast-unknown"
        result = reconcile(e, now=1000)
        self.assertIn("unresolved-transaction-do-not-replay", result["blockers"])
        self.assertEqual(result["jobs"][0]["decision"], "hold")
    def test_absent_assignment_unknown_process_revoked_job_held(self):
        e = evidence(); e["jobs"][0].update(job_id=314476, assignment="absent", process="ssh-failed")
        result = reconcile(e, now=1000)
        self.assertEqual(result["jobs"][0]["decision"], "hold")
        self.assertIn("physical-process-state-unknown", result["jobs"][0]["reasons"])
    def test_duplicate_identity_blocks_all(self):
        e = evidence(); other = copy.deepcopy(e["jobs"][0]); other["job_id"] = 456; e["jobs"].append(other)
        result = reconcile(e, now=1000)
        self.assertIn("duplicate-live-identity-or-ip", result["blockers"])
        self.assertTrue(all(row["decision"] == "hold" for row in result["jobs"]))
    def test_stale_and_unfenced_authority_blocks(self):
        e = evidence(); e.update(chain_observed_at=1, authority_fenced=False)
        result = reconcile(e, now=1000)
        self.assertEqual(result["jobs"][0]["decision"], "hold")
        self.assertIn("old-controller-not-proven-fenced", result["blockers"])


class LocalDeltaSafety(unittest.TestCase):
    def test_prior_hash_required_and_inputs_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            b = archive(root / "base.tar.gz", {"local/state": b"old", "local/receipt": b"keep"})
            verify_archive(root / "base.tar.gz", root / "base")
            archive(root / "delta.tar.gz", {"local/state": b"new"})
            d = verify_archive(root / "delta.tar.gz", root / "delta")
            d.update(base_artifact_plaintext_sha256="a" * 64, deleted_files=[])
            d["files"]["local/state"]["prior_sha256"] = b["files"]["local/state"]["sha256"]
            (root / "delta/manifest.json").write_text(json.dumps(d))
            result = merge_module.merge(root / "base", root / "delta", root / "merged", "a" * 64)
            self.assertEqual(result["delta_files"], 1)
            self.assertEqual((root / "merged/local/state").read_bytes(), b"new")
            self.assertEqual((root / "base/local/state").read_bytes(), b"old")
            d["files"]["local/state"]["prior_sha256"] = "b" * 64
            (root / "delta/manifest.json").write_text(json.dumps(d))
            with self.assertRaises(RecoveryError):
                merge_module.merge(root / "base", root / "delta", root / "blocked", "a" * 64)


@unittest.skipUnless(shutil.which("node"), "node required")
class EndToEnd(unittest.TestCase):
    def test_private_plaintext_restore_resume_tamper_and_host_fence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); fixture = root / "fixture"
            subprocess.run(["node", str(BASE / "tests/make-fixture.mjs"), str(fixture)], check=True, capture_output=True)
            metadata = fixture / "metadata"; metadata.mkdir()
            uid, gid = os.getuid(), os.getgid()
            username = "fixture-user" if uid else "root"
            groupname = "fixture-group" if gid else "root"
            accounts = "root:x:0:0:root:/root:/bin/sh\n"
            if uid: accounts += f"{username}:x:{uid}:{gid}:fixture:/home/fixture:/bin/sh\n"
            groups = "root:x:0:\n"
            if gid: groups += f"{groupname}:x:{gid}:\n"
            (metadata / "accounts.txt").write_text(accounts)
            (metadata / "groups.txt").write_text(groups)
            (metadata / "uname.txt").write_text("Linux test 6.8.0 x86_64 GNU/Linux\n")
            (fixture / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
            (metadata / "dpkg-packages.txt").write_text("python3\t3.12-test\tamd64\n")
            (metadata / "systemd.json").write_text(json.dumps({"example.service": {
                "User":username,"Group":groupname,"WorkingDirectory":"/var/lib/fixture",
                "StateDirectory":"fixture","RuntimeDirectory":"fixture", "ExecStart":"{ path=/usr/bin/missing-runtime ; }"}}))
            (fixture / "source.py").write_text("url='https://user:secret@old.example.invalid/private?token=abc'\nroot='/opt/wdi'\n")
            # A real SQLite DB validates read-only integrity checks.
            db = fixture / "state.sqlite"
            with sqlite3.connect(db) as conn:
                conn.execute("CREATE TABLE receipts (tx TEXT PRIMARY KEY)")
                conn.execute("INSERT INTO receipts VALUES ('synthetic-finalized')")
            plain = root / "snapshot.tar.gz"
            archive(plain, {str(p.relative_to(fixture)): p.read_bytes() for p in fixture.rglob("*") if p.is_file()})
            work = root / "work"; cache = work / "asset-cache"; cache.mkdir(parents=True)
            asset = cache / "snapshot.tar.gz"
            shutil.copyfile(plain, asset)
            runtime = cache / "runtime.tar.gz"
            archive(runtime, {"opt/runtime/bundle.tar.gz": b"synthetic-runtime"})
            immutable = cache / "prepared-image.tar.xz"
            immutable.write_bytes(b"synthetic-immutable-image")
            manifest = root / "release.json"
            manifest.write_text(json.dumps({"schema":2,"repository":"owner/Accurast","tag":"synthetic-test",
                "artifacts":[{"name":asset.name,"sha256":sha(asset),"bytes":asset.stat().st_size,
                              "kind":"snapshot","destination":"host"},
                             {"name":runtime.name,"sha256":sha(runtime),"bytes":runtime.stat().st_size,
                              "kind":"local-state","destination":"host-runtime"},
                             {"name":immutable.name,"sha256":sha(immutable),"bytes":immutable.stat().st_size,
                              "kind":"immutable","destination":"images/prepared-image.tar.xz"}]}))
            cmd = [sys.executable, str(BASE / "scripts/recover.py"), "restore", "--offline", "--manifest", str(manifest),
                   "--work", str(work)]
            first = subprocess.run(cmd, check=True, capture_output=True)
            report = json.loads(first.stdout)
            self.assertEqual(report["artifacts"][0]["vault"]["profiles_verified"], 1)
            self.assertEqual(report["artifacts"][0]["sqlite_databases_verified"], 1)
            self.assertFalse(report["separate_recovery_key_required"])
            self.assertFalse(report["outer_backup_encryption"])
            second = subprocess.run(cmd, check=True, capture_output=True)
            self.assertTrue(json.loads(second.stdout)["artifacts"][0]["resumed"])
            target = root / "offline-root"
            subprocess.run([sys.executable, str(BASE / "scripts/stage-host.py"), "--snapshot", str(work / "restored/host"),
                            "--target-root", str(target), "--config", str(BASE / "config/recovery.example.json"),
                            "--supplement", str(work / "restored/host-runtime"), "--artifact-work", str(work),
                            "--release-manifest", str(manifest)],
                           check=True, capture_output=True)
            fence = target / "etc/systemd/system/example.service.d/00-disaster-recovery-fence.conf"
            self.assertIn("ConditionPathExists=", fence.read_text())
            self.assertFalse((target / "var/lib/accurast-recovery/LIVE-RECONCILIATION-APPROVED").exists())
            self.assertEqual((target / "opt/runtime/bundle.tar.gz").read_bytes(), b"synthetic-runtime")
            self.assertEqual((target / "var/lib/wdi-acurast-native/artifacts/prepared-image.tar.xz").read_bytes(), b"synthetic-immutable-image")
            conflict_archive = root / "conflict.tar.gz"
            archive(conflict_archive, {"etc/systemd/system/example.service": b"changed-service"})
            verify_archive(conflict_archive, root / "conflict")
            conflict = subprocess.run([sys.executable, str(BASE / "scripts/stage-host.py"), "--snapshot", str(work / "restored/host"),
                            "--target-root", str(root / "rejected-target"), "--config", str(BASE / "config/recovery.example.json"),
                            "--supplement", str(root / "conflict")], capture_output=True)
            self.assertNotEqual(conflict.returncode, 0)
            self.assertIn(b"Supplement changes an authoritative file", conflict.stderr)
            config = json.loads((BASE / "config/recovery.example.json").read_text())
            config.update(domain_overrides={"old.example.invalid":"replacement.example.invalid"})
            prepared = prep_module.prepare(work / "restored/host", target, config)
            self.assertEqual(prepared["services_started"], 0)
            self.assertFalse(prepared["packages_installed"])
            self.assertTrue((target / "run/fixture").is_dir())
            self.assertIn(":!:", (target / "etc/shadow").read_text())
            self.assertIn("exit 101", (target / "usr/sbin/policy-rc.d").read_text())
            report = audit_module.audit(work / "restored/host", target, config)
            self.assertTrue(any(row["path"] == "/usr/bin/missing-runtime" for row in report["missing_unit_references"]))
            serialized = json.dumps(report)
            self.assertNotIn("token=abc", serialized)
            self.assertNotIn("user:secret", serialized)
            self.assertIn("replacement.example.invalid", serialized)
            bad_config = dict(config, target_architecture="aarch64")
            with self.assertRaises(RecoveryError): prep_module.prepare(work / "restored/host", target, bad_config)
            (work / "restored/host/var/lib/wdi-acurast-manager/workers.json").write_text("tampered")
            failed = subprocess.run(cmd, capture_output=True)
            self.assertNotEqual(failed.returncode, 0)


class PrivateDownload(unittest.TestCase):
    def test_public_repository_rejected(self):
        manifest = {"repository": "owner/Accurast"}
        with patch("recover.shutil.which", return_value="tool"), patch("recover.command", return_value=b'{"private": false, "full_name": "owner/Accurast"}'):
            with self.assertRaises(RecoveryError): preflight(manifest)
    def test_downloaded_asset_hash_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = Path(temp).resolve()
            data = b"downloaded-private-state"
            artifact = {"name": "state.tar.gz", "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            manifest = {"repository": "owner/Accurast", "tag": "test"}
            def download(args, label):
                (Path(args[args.index("--dir") + 1]) / artifact["name"]).write_bytes(data)
                return b""
            with patch("recover.command", side_effect=download):
                out = download_asset(manifest, artifact, cache, offline=False)
            self.assertEqual(out.read_bytes(), data)
            out.write_bytes(b"tampered")
            with self.assertRaises(RecoveryError): download_asset(manifest, artifact, cache, offline=True)


if __name__ == "__main__":
    unittest.main()
