#!/usr/bin/env python3
"""Validate original Linux POSIX ACLs; apply only to an explicitly staged offline root."""
import argparse
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import struct
import sys

sys.path.insert(0, str(Path(__file__).parent))
from recover import RecoveryError, relative, require, sha, snapshot_file, write_json

UNDEFINED = 0xFFFFFFFF
TAGS = {1: "owner", 2: "user", 4: "owning-group", 8: "group", 16: "mask", 32: "other"}
RANK = {1: 0, 2: 1, 4: 2, 8: 3, 16: 4, 32: 5}


def parse_acl(value, known_uids, known_gids):
    require(isinstance(value, dict), "Invalid ACL value record")
    require(isinstance(value.get("base64"), str) and len(value["base64"]) <= 2 * 1024 * 1024, "Oversized ACL encoded value")
    try: raw = base64.b64decode(value["base64"], validate=True)
    except (KeyError, TypeError, ValueError): raise RecoveryError("Invalid ACL base64")
    require(hashlib.sha256(raw).hexdigest() == value.get("sha256"), "ACL binary digest mismatch")
    require(28 <= len(raw) <= 1024 * 1024 and (len(raw) - 4) % 8 == 0, "Invalid ACL binary size")
    require(struct.unpack_from("<I", raw)[0] == 2, "Unsupported Linux POSIX ACL version")
    entries, seen, order = [], set(), []
    for offset in range(4, len(raw), 8):
        tag, perms, ident = struct.unpack_from("<HHI", raw, offset)
        require(tag in TAGS and 0 <= perms <= 7, "Invalid ACL tag or permission bits")
        require((tag, ident) not in seen, "Duplicate ACL entry")
        seen.add((tag, ident)); order.append((RANK[tag], ident))
        if tag in (2, 8):
            require(ident != UNDEFINED and ident in (known_uids if tag == 2 else known_gids), "ACL named identity missing from captured accounts")
        else:
            require(ident == UNDEFINED, "Unexpected numeric ID on ACL base entry")
        entries.append({"tag": tag, "permissions": perms, "id": ident})
    require(order == sorted(order), "Noncanonical ACL entry order")
    for tag in (1, 4, 32):
        require(sum(e["tag"] == tag for e in entries) == 1, "Missing ACL base entry")
    require(sum(e["tag"] == 16 for e in entries) <= 1, "Duplicate ACL mask")
    require(not any(e["tag"] in (2, 8) for e in entries) or any(e["tag"] == 16 for e in entries), "Named ACL entries require a mask")
    perms = {e["tag"]: e["permissions"] for e in entries if e["tag"] not in (2, 8)}
    mode = (perms[1] << 6) | (perms.get(16, perms[4]) << 3) | perms[32]
    return raw, entries, mode


def numeric_accounts(path, field=2):
    result = {}
    for line in path.read_text().splitlines():
        fields = line.split(":")
        require(len(fields) > field and fields[field].isdigit(), "Invalid numeric account metadata")
        ident = int(fields[field])
        require(ident not in result or result[ident] == fields[0], "Ambiguous numeric account identity")
        result[ident] = fields[0]
    return result


def restore_acls(snapshot, acl_root, target, config, apply=False):
    snapshot, acl_root, target = Path(snapshot).absolute(), Path(acl_root).absolute(), Path(target).absolute()
    require(target.resolve() != Path("/") and target.resolve() not in (snapshot.resolve(), acl_root.resolve()),
            "Live root and source snapshots are forbidden ACL targets")
    require(not target.is_symlink() and all(not p.is_symlink() for p in target.parents), "Offline ACL root has symlinked parents")
    require(config.get("controller_mode") == "disabled-until-reconciled", "Controllers must remain disabled")
    staged_path = target / "var/lib/accurast-recovery/staging-report.json"
    require(staged_path.is_file() and not staged_path.is_symlink(), "ACL target was not staged")
    require(not (target / "var/lib/accurast-recovery/LIVE-RECONCILIATION-APPROVED").exists(), "Live marker present; refusing ACL restoration")
    staged = json.loads(staged_path.read_text())
    require(staged["source_manifest_sha256"] == sha(snapshot / "manifest.json"), "ACL target snapshot mismatch")
    if apply:
        require(platform.system() == "Linux", "Applying Linux POSIX ACL xattrs requires Linux; validation only on this platform")
        require(os.geteuid() == 0, "Applying original ACLs requires root after numeric ownership preparation")
    policy_file = snapshot_file(acl_root, "metadata/posix-acls.json")
    policy = json.loads(policy_file.read_text())
    require(policy.get("schema") == 1 and isinstance(policy.get("entries"), dict), "Unsupported ACL policy schema")
    source_users = numeric_accounts(snapshot_file(snapshot, "metadata/accounts.txt"))
    source_groups = numeric_accounts(snapshot_file(snapshot, "metadata/groups.txt"))
    require(not (target / "etc").is_symlink(), "Target account directory cannot be symlinked")
    for account_path in (target / "etc/passwd", target / "etc/group"):
        require(not account_path.is_symlink(), "Target account file cannot be symlinked")
    target_users = numeric_accounts(target / "etc/passwd") if (target / "etc/passwd").is_file() else {}
    target_groups = numeric_accounts(target / "etc/group") if (target / "etc/group").is_file() else {}
    mappings = config.get("source_path_mapping", {})
    def mapped(name):
        absolute = "/" + name
        for before in sorted(mappings, key=len, reverse=True):
            if absolute == before or absolute.startswith(before.rstrip("/") + "/"):
                absolute = mappings[before].rstrip("/") + absolute[len(before):]; break
        return relative(absolute.lstrip("/"))
    prepared, named_uids, named_gids, owner_uids, owner_gids = [], set(), set(), set(), set()
    for name, record in policy["entries"].items():
        relative(name)
        require(record.get("kind") in ("file", "directory"), "ACL path type must be file or directory")
        uid, gid = record["source_uid"], record["source_gid"]
        require(uid in source_users and gid in source_groups, "ACL owner identity missing from captured accounts")
        owner_uids.add(uid); owner_gids.add(gid)
        path = target.joinpath(*mapped(name).parts)
        require(not path.is_symlink() and all(not p.is_symlink() for p in path.parents if p == target or target in p.parents), "ACL target or parent is symlinked")
        require(path.is_file() if record["kind"] == "file" else path.is_dir(), "Recorded ACL target is missing or has changed type")
        mode = record["source_mode"]
        if isinstance(mode, str): mode = int(mode, 8)
        attrs = {}
        for kind in ("access", "default"):
            value = record.get(kind)
            require(kind != "default" or value is None or record["kind"] == "directory", "Default ACL is valid only on a directory")
            if value is None:
                if kind != "default" or record["kind"] == "directory":
                    attrs["system.posix_acl_" + kind] = None
                continue
            raw, entries, acl_mode = parse_acl(value, set(source_users), set(source_groups))
            require(kind != "access" or acl_mode == (mode & 0o777), "Access ACL mask disagrees with captured mode")
            named_uids.update(e["id"] for e in entries if e["tag"] == 2)
            named_gids.update(e["id"] for e in entries if e["tag"] == 8)
            attrs["system.posix_acl_" + kind] = raw
        require(any(v is not None for v in attrs.values()), "Empty ACL entry should not be in ACL policy")
        if apply:
            st = path.stat()
            require((st.st_uid, st.st_gid) == (uid, gid), "Apply original numeric ownership before ACLs")
            require(stat.S_IMODE(st.st_mode) & 0o777 == mode & 0o777, "Offline file mode differs from captured ACL mode")
        prepared.append((path, attrs))
    identity_issues = [{"kind":"user","id":uid,"issue":"missing-or-name-mismatch"} for uid in sorted(named_uids | owner_uids) if target_users.get(uid) != source_users[uid]]
    identity_issues += [{"kind":"group","id":gid,"issue":"missing-or-name-mismatch"} for gid in sorted(named_gids | owner_gids) if target_groups.get(gid) != source_groups[gid]]
    if apply:
        require(not identity_issues, "ACL users/groups must be materialized with original numeric identities and names first")
        for path, attrs in prepared:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                for name, raw in attrs.items():
                    if raw is None:
                        try: os.removexattr(fd, name)
                        except OSError as error:
                            if error.errno != errno.ENODATA: raise
                        continue
                    os.setxattr(fd, name, raw)
                    require(os.getxattr(fd, name) == raw, "Restored ACL read-back mismatch")
            finally: os.close(fd)
    return {"schema": 1, "policy_sha256": sha(policy_file), "source_manifest_sha256": staged["source_manifest_sha256"],
            "recorded_acl_paths_validated": len(prepared), "named_user_ids": sorted(named_uids),
            "named_group_ids": sorted(named_gids), "target_account_identity_issues": identity_issues,
            "applied": apply, "platform": platform.system(),
            "status": "applied-and-read-back-verified" if apply else "validated-not-applied",
            "services_started": 0, "live_actions_allowed": False,
            "coverage": policy.get("coverage", policy.get("roots", []))}


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--snapshot", required=True)
    p.add_argument("--acl-root", required=True, help="Verified restored ACL metadata supplement")
    p.add_argument("--target-root", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--apply-xattrs", action="store_true", help="Apply only to the offline Linux root; root and prior numeric ownership are required")
    args = p.parse_args()
    result = restore_acls(args.snapshot, args.acl_root, args.target_root, json.loads(Path(args.config).read_text()), args.apply_xattrs)
    write_json(Path(args.target_root) / "var/lib/accurast-recovery/acl-restoration.json", result)
    print(json.dumps(result))


if __name__ == "__main__":
    try: main()
    except Exception as error:
        print(str(error) if isinstance(error, RecoveryError) else "ACL restoration failed; filesystem xattr support and permissions are required", file=sys.stderr)
        sys.exit(1)
