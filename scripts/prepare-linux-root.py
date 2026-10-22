#!/usr/bin/env python3
"""Prepare service identities and directories in an OFFLINE staged Linux root."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import sys

sys.path.insert(0, str(Path(__file__).parent))
from recover import RecoveryError, private_dir, relative, require, restore_directory_metadata, sha, snapshot_file, write_json

ARCH_ALIASES = {"amd64": "x86_64", "arm64": "aarch64"}


def arch(value):
    return ARCH_ALIASES.get(value, value)


def captured_arch(snapshot):
    text = snapshot_file(snapshot, "metadata/uname.txt").read_text()
    found = re.findall(r"\b(x86_64|aarch64|arm64|amd64)\b", text)
    require(found, "Captured host architecture unavailable")
    require(len(set(map(arch, found))) == 1, "Ambiguous captured host architecture")
    return arch(found[0])


def os_release(path):
    result = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            name, value = line.split("=", 1)
            result[name] = value.strip('"\'')
    return {key: result.get(key) for key in ("ID", "VERSION_ID")}


def validate_platform(snapshot, config, native=False):
    source_arch = captured_arch(snapshot)
    target_arch = config.get("target_architecture", "match-captured-host")
    require(config.get("target_platform") == "linux", "Replacement target must be Linux")
    require(target_arch == "match-captured-host" or arch(target_arch) == source_arch,
            "Replacement architecture differs from captured runtime; migration requires separate validated binaries")
    source_os = os_release(snapshot_file(snapshot, "etc/os-release"))
    if native:
        require(platform.system() == "Linux" and arch(platform.machine()) == source_arch,
                "Native preparation requires matching Linux host architecture")
        require(os_release(Path("/etc/os-release")) == source_os,
                "Native preparation requires captured Linux distribution/version")
    return {"captured_architecture": source_arch, "captured_os": source_os, "native_platform_checked": native}


def table(path, columns):
    rows = {}
    if not path.exists():
        return rows
    require(not path.is_symlink(), "Account file cannot be a symlink")
    for line in path.read_text().splitlines():
        fields = line.split(":")
        require(len(fields) == columns and fields[0] and fields[0] not in rows, "Invalid account table")
        rows[fields[0]] = fields
    return rows


def safe_target(root, absolute):
    require(absolute.startswith("/"), "Expected an absolute service path")
    if absolute == "/":
        return root
    p = root.joinpath(*relative(absolute.lstrip("/")).parts)
    require(not p.is_symlink(), "Service path is symlinked; review before preparation")
    require(all(not q.is_symlink() for q in p.parents if q != root and root in q.parents),
            "Service path has a symlinked parent")
    return p


def write_table(path, rows, mode):
    content = "".join(":".join(row) + "\n" for row in rows.values())
    with path.open("w") as stream:
        stream.write(content)
    path.chmod(mode)


def prepare(snapshot, target, config, ownership=False, native=False):
    snapshot, target = Path(snapshot).resolve(), Path(target).absolute()
    require(target.resolve() != Path("/") and target.resolve() != snapshot,
            "Live root and snapshot are forbidden preparation targets")
    private_dir(target)
    report_path = target / "var/lib/accurast-recovery/staging-report.json"
    require(report_path.is_file(), "Stage the verified host before preparing Linux accounts")
    staged = json.loads(report_path.read_text())
    require(staged["source_manifest_sha256"] == sha(snapshot / "manifest.json"), "Staged root belongs to another snapshot")
    require(config.get("controller_mode") == "disabled-until-reconciled", "Controllers must remain disabled")
    require(not (target / "var/lib/accurast-recovery/LIVE-RECONCILIATION-APPROVED").exists(), "Live marker is present; refusing offline preparation")
    require(not ownership or os.geteuid() == 0, "Ownership restoration requires root")
    require(not ownership or platform.system() == "Linux", "Original numeric ownership is restored only on Linux")
    platform_report = validate_platform(snapshot, config, native)
    units = json.loads(snapshot_file(snapshot, "metadata/systemd.json").read_text())
    source_users = table(snapshot_file(snapshot, "metadata/accounts.txt"), 7)
    source_groups = table(snapshot_file(snapshot, "metadata/groups.txt"), 4)
    uid_map = {int(row[2]): row for row in source_users.values()}
    gid_map = {int(row[2]): row for row in source_groups.values()}
    manifest = json.loads((snapshot / "manifest.json").read_text())
    uid_need = {0, *staged.get("required_uids", [])}
    gid_need = {0, *staged.get("required_gids", [])}
    for record in list(manifest["files"].values()) + list(manifest.get("directories", {}).values()):
        uid_need.add(int(record.get("source_uid", 0))); gid_need.add(int(record.get("source_gid", 0)))
    for props in units.values():
        for key, source, needed in (("User", source_users, uid_need), ("Group", source_groups, gid_need)):
            value = props.get(key)
            if value:
                require(value in source or value.isdecimal(), "Unresolved captured service account")
                needed.add(int(source[value][2]) if value in source else int(value))
    require(uid_need <= set(uid_map) and gid_need <= set(gid_map), "Captured file owner lacks account metadata")
    for uid in uid_need:
        gid_need.add(int(uid_map[uid][3]))
    require(gid_need <= set(gid_map), "Captured primary group missing")
    etc = safe_target(target, "/etc"); etc.mkdir(mode=0o755, exist_ok=True)
    users, groups = table(etc / "passwd", 7), table(etc / "group", 4)
    shadow = table(etc / "shadow", 9)
    for gid in sorted(gid_need):
        row = gid_map[gid]; name = row[0]
        require(not any(int(x[2]) == gid and x[0] != name for x in groups.values()), "Replacement group ID collision")
        require(name not in groups or int(groups[name][2]) == gid, "Replacement group name collision")
        # Preserve reviewed membership only for accounts actually materialized.
        members = [m for m in row[3].split(",") if m in source_users and int(source_users[m][2]) in uid_need]
        groups[name] = [name, "x", str(gid), ",".join(members)]
    dirs = set()
    for uid in sorted(uid_need):
        row = uid_map[uid]; name = row[0]
        require(not any(int(x[2]) == uid and x[0] != name for x in users.values()), "Replacement user ID collision")
        require(name not in users or (int(users[name][2]), int(users[name][3])) == (uid, int(row[3])), "Replacement account identity collision")
        users[name] = [name, "x", str(uid), row[3], row[4], row[5], row[6]]
        # No password hash is invented or copied; all newly introduced accounts are locked.
        shadow.setdefault(name, [name, "!", "0", "0", "99999", "7", "", "", ""])
        if row[5].startswith("/") and row[5] not in ("/", "/nonexistent", "/dev/null"):
            dirs.add((row[5], uid, int(row[3])))
    mappings = config.get("source_path_mapping", {})
    def remap(value):
        for before in sorted(mappings, key=len, reverse=True):
            if value == before or value.startswith(before.rstrip("/") + "/"):
                return mappings[before].rstrip("/") + value[len(before):]
        return value
    unresolved = []
    for unit, props in units.items():
        user = props.get("User") or "root"
        uid = int(user) if user.isdecimal() else int(source_users[user][2])
        gid = int(uid_map[uid][3])
        group = props.get("Group")
        if group: gid = int(group) if group.isdecimal() else int(source_groups[group][2])
        work = props.get("WorkingDirectory", "").lstrip("-")
        if work and work != "/":
            if "%" in work or not work.startswith("/"): unresolved.append({"unit": unit, "field": "WorkingDirectory"})
            else: dirs.add((work, uid, gid))
        for field, prefix in (("RuntimeDirectory", "/run/"), ("StateDirectory", "/var/lib/"), ("CacheDirectory", "/var/cache/"), ("LogsDirectory", "/var/log/")):
            for value in props.get(field, "").split():
                if "%" in value or ":" in value or value.startswith("/"):
                    unresolved.append({"unit": unit, "field": field}); continue
                relative(value)
                dirs.add((prefix + value, uid, gid))
    for name, uid, gid in dirs:
        dest = safe_target(target, remap(name))
        if not dest.exists():
            dest.mkdir(parents=True, mode=0o750)
        require(dest.is_dir(), "Required service directory is not a directory")
        if ownership: os.chown(dest, uid, gid)
    policy = safe_target(target, "/usr/sbin/policy-rc.d")
    policy_text = "#!/bin/sh\n# Offline disaster-recovery root: do not start services.\nexit 101\n"
    require(not policy.exists() or policy.read_text() == policy_text,
            "Existing offline policy-rc.d requires review; refusing to replace it")
    write_table(etc / "passwd", users, 0o644)
    write_table(etc / "group", groups, 0o644)
    write_table(etc / "shadow", shadow, 0o600)
    control = private_dir(target / "var/lib/accurast-recovery")
    # Defend future package installation via standard init helpers. Package
    # installation itself is deliberately outside this offline preparation step.
    policy.parent.mkdir(parents=True, exist_ok=True)
    if not policy.exists():
        policy.write_text(policy_text)
        policy.chmod(0o755)
    package_rows = []
    for line in snapshot_file(snapshot, "metadata/dpkg-packages.txt").read_text().splitlines():
        fields = line.split("\t")
        require(len(fields) == 3, "Invalid captured package/version record")
        package_rows.append(dict(zip(("package", "version", "architecture"), fields)))
    write_json(control / "packages.lock.json", {"packages": package_rows, "installed_by_recovery": False})
    if ownership:
        directory_permissions = restore_directory_metadata(target, manifest.get("directories", {}),
            lambda name: relative(remap("/" + name).lstrip("/")), True)
    else:
        # A validation/preparation pass must not strip SGID already restored by
        # a preceding explicit Linux staging pass. It performs no final chmod.
        special_count = sum(bool((int(r["source_mode"],8) if isinstance(r["source_mode"],str) else r["source_mode"]) & 0o7000)
                            for r in manifest.get("directories", {}).values())
        directory_permissions = {"special_modes_captured":special_count,"special_modes_restored":0,
                                 "special_modes_deferred":special_count,"ownership_applied":False,
                                 "final_directory_mode_changes_performed":False}
    result = {**platform_report, "accounts_materialized": len(uid_need), "groups_materialized": len(gid_need),
              "service_directories_prepared": len(dirs), "unresolved_directory_properties": unresolved,
              "package_versions_recorded": len(package_rows), "packages_installed": False,
              "ownership_applied": ownership, "directory_permissions": directory_permissions,
              "services_started": 0, "live_actions_allowed": False}
    write_json(control / "linux-preparation.json", result)
    return result


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--snapshot", required=True)
    p.add_argument("--target-root", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--apply-ownership", action="store_true")
    p.add_argument("--require-native-platform", action="store_true", help="Reject Linux distro/version/CPU mismatch before native provisioning")
    args = p.parse_args()
    result = prepare(args.snapshot, args.target_root, json.loads(Path(args.config).read_text()), args.apply_ownership, args.require_native_platform)
    print(json.dumps(result))


if __name__ == "__main__":
    try: main()
    except Exception as error:
        print(str(error) if isinstance(error, RecoveryError) else "Offline Linux preparation failed closed", file=sys.stderr)
        sys.exit(1)
