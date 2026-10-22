import base64
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / "scripts"))
from recover import RecoveryError, sha
spec = importlib.util.spec_from_file_location("restore_acls", BASE / "scripts/restore-acls.py")
acl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acl)


def value(entries):
    raw = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)
    return {"base64": base64.b64encode(raw).decode(), "sha256": hashlib.sha256(raw).hexdigest()}


ACL = [(1, 7, 0xFFFFFFFF), (2, 5, 1000), (4, 0, 0xFFFFFFFF), (16, 5, 0xFFFFFFFF), (32, 0, 0xFFFFFFFF)]


def inventory(root, files):
    records = {}
    for name, data in files.items():
        p = root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data)
        records[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    (root / "manifest.json").write_text(json.dumps({"files": records}))


class PosixAclSafety(unittest.TestCase):
    def test_native_binary_policy_and_numeric_identity_validation(self):
        raw, rows, mode = acl.parse_acl(value(ACL), {0, 1000}, {0})
        self.assertEqual(mode, 0o750)
        self.assertEqual(rows[1]["id"], 1000)
        with self.assertRaises(RecoveryError): acl.parse_acl(value(ACL), {0}, {0})
        with self.assertRaises(RecoveryError): acl.parse_acl(value([e for e in ACL if e[0] != 16]), {0, 1000}, {0})
        invalid = list(ACL); invalid[1] = (2, 8, 1000)
        with self.assertRaises(RecoveryError): acl.parse_acl(value(invalid), {0, 1000}, {0})
    def test_live_root_rejected_before_xattr_operation(self):
        with patch.object(acl.os, "setxattr", create=True) as setxattr:
            with self.assertRaises(RecoveryError):
                acl.restore_acls("/nonexistent-snapshot", "/nonexistent-acls", "/", {"controller_mode":"disabled-until-reconciled"}, apply=True)
            setxattr.assert_not_called()
    def test_mac_validation_only_and_unsupported_filesystem_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); source=root/"source"; extra=root/"extra"; target=root/"offline"
            source.mkdir(); extra.mkdir(); target.mkdir()
            uid, gid = os.getuid(), os.getgid()
            users = {0:"root", 1000:"operator", uid:"fixture"}
            groups = {0:"root", gid:"fixture-group"}
            passwd = "".join(f"{name}:x:{ident}:{gid}::/nonexistent:/bin/false\n" for ident,name in users.items()).encode()
            group = "".join(f"{name}:x:{ident}:\n" for ident,name in groups.items()).encode()
            inventory(source, {"metadata/accounts.txt":passwd, "metadata/groups.txt":group})
            policy = {"schema":1, "entries":{"var/lib/runtime/state":{"kind":"file","source_uid":uid,"source_gid":gid,
                "source_mode":0o750,"access":value(ACL),"default":None}}}
            inventory(extra, {"metadata/posix-acls.json":json.dumps(policy).encode()})
            state=target/"var/lib/runtime/state";state.parent.mkdir(parents=True);state.write_bytes(b"unchanged");state.chmod(0o750)
            control=target/"var/lib/accurast-recovery";control.mkdir()
            (control/"staging-report.json").write_text(json.dumps({"source_manifest_sha256":sha(source/"manifest.json")}))
            (target/"etc").mkdir();(target/"etc/passwd").write_bytes(passwd);(target/"etc/group").write_bytes(group)
            config={"controller_mode":"disabled-until-reconciled"}
            with patch.object(acl.platform,"system",return_value="Darwin"), patch.object(acl.os,"setxattr", create=True) as setxattr:
                result=acl.restore_acls(source,extra,target,config)
                self.assertFalse(result["applied"]);self.assertEqual(result["recorded_acl_paths_validated"],1)
                with self.assertRaises(RecoveryError): acl.restore_acls(source,extra,target,config,apply=True)
                setxattr.assert_not_called()
            with patch.object(acl.platform,"system",return_value="Linux"), patch.object(acl.os,"geteuid",return_value=0), \
                 patch.object(acl.os,"setxattr",side_effect=OSError(errno.ENOTSUP,"unsupported"),create=True):
                with self.assertRaises(OSError): acl.restore_acls(source,extra,target,config,apply=True)
            replaced = passwd.decode().replace(users[1000] + ":", "different-user:")
            (target/"etc/passwd").write_text(replaced)
            with patch.object(acl.platform,"system",return_value="Linux"), patch.object(acl.os,"geteuid",return_value=0), \
                 patch.object(acl.os,"setxattr",create=True) as setxattr:
                with self.assertRaises(RecoveryError): acl.restore_acls(source,extra,target,config,apply=True)
                setxattr.assert_not_called()
            self.assertEqual(state.read_bytes(),b"unchanged")
    def test_sidecar_acl_validated_but_not_reapplied_or_recreated(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp).resolve();source=root/"source";extra=root/"extra";target=root/"offline"
            source.mkdir();extra.mkdir();target.mkdir()
            passwd=b"root:x:0:0::/root:/bin/sh\noperator:x:1000:0::/nonexistent:/bin/false\n"
            inventory(source,{"metadata/accounts.txt":passwd,"metadata/groups.txt":b"root:x:0:\n"})
            name="var/lib/runtime/state.sqlite-wal"
            policy={"schema":1,"entries":{name:{"kind":"file","source_uid":0,"source_gid":0,"source_mode":0o750,"access":value(ACL),"default":None}}}
            policy_path="metadata/posix-acls-accounting.json"
            inventory(extra,{policy_path:json.dumps(policy).encode()})
            quarantine="var/lib/accurast-recovery/forensic-sqlite-sidecars/"+name
            saved=target/quarantine;saved.parent.mkdir(parents=True);saved.write_bytes(b"forensic-wal")
            control=target/"var/lib/accurast-recovery"
            (control/"staging-report.json").write_text(json.dumps({"source_manifest_sha256":sha(source/"manifest.json"),
                "sqlite_sidecar_quarantine":[{"original_path":name,"quarantine_path":quarantine,"sha256":sha(saved)}]}))
            with patch.object(acl.platform,"system",return_value="Linux"),patch.object(acl.os,"geteuid",return_value=0),patch.object(acl.os,"setxattr",create=True)as setxattr:
                result=acl.restore_acls(source,extra,target,{"controller_mode":"disabled-until-reconciled"},apply=True,policy_path=policy_path)
                self.assertEqual(result["quarantined_sidecar_acl_paths"],[name])
                self.assertEqual(result["applicable_acl_paths"],0)
                self.assertFalse((target/name).exists());setxattr.assert_not_called()


if __name__ == "__main__": unittest.main()
