#!/usr/bin/env python3
"""Assemble an OFFLINE Linux filesystem from a verified snapshot, never start it."""
import argparse
import json
import os
from pathlib import Path
import platform
import posixpath
import shutil
import sys

sys.path.insert(0, str(Path(__file__).parent))
from recover import RecoveryError, private_dir, relative, require, sha, verify_tree, verify_host, write_json


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--snapshot", required=True, help="Verified restored host directory")
    p.add_argument("--target-root", required=True, help="Empty offline directory or mounted replacement root; never /")
    p.add_argument("--config", required=True)
    p.add_argument("--preserve-ownership", action="store_true", help="Requires root; restore captured uid/gid numerically")
    args = p.parse_args()
    source = Path(args.snapshot).resolve()
    target = Path(args.target_root).absolute()
    require(target.resolve() != Path("/") and target != source and source not in target.parents and target not in source.parents,
            "Target must be an independent offline root")
    target = private_dir(target)
    require(not any(target.iterdir()), "Offline target must be empty")
    manifest = json.loads((source / "manifest.json").read_text())
    require((source / ".isolation.json").is_file(), "Use recover restore before staging")
    verify_tree(source, manifest)
    verify_host(source, manifest)
    config = json.loads(Path(args.config).read_text())
    require(config.get("controller_mode") == "disabled-until-reconciled", "Controller mode must remain disabled")
    require(not args.preserve_ownership or os.geteuid() == 0, "Root required to restore ownership")
    mappings = config.get("source_path_mapping", {})
    for before, after in mappings.items():
        require(before.startswith("/") and after.startswith("/"), "Path mappings must be absolute")
        relative(before.lstrip("/")); relative(after.lstrip("/"))
    def mapped(name):
        absolute = "/" + name
        for before in sorted(mappings, key=len, reverse=True):
            if absolute == before or absolute.startswith(before.rstrip("/") + "/"):
                absolute = mappings[before].rstrip("/") + absolute[len(before):]
                break
        return relative(absolute.lstrip("/"))
    count, units, mapped_names = 0, set(), set()
    for name, rec in manifest["files"].items():
        if name.startswith("metadata/"):
            continue
        dest_rel = mapped(name)
        require(str(dest_rel) not in mapped_names, "Path mapping collision")
        mapped_names.add(str(dest_rel))
        dest = target.joinpath(*dest_rel.parts)
        private_dir(dest.parent)
        shutil.copyfile(source / name, dest)
        mode = rec.get("source_mode", 0o600)
        if isinstance(mode, str): mode = int(mode, 8)
        dest.chmod(mode & 0o777)  # never restore setuid/setgid
        if args.preserve_ownership:
            os.chown(dest, rec.get("source_uid", 0), rec.get("source_gid", 0))
        if name.startswith("etc/systemd/system/") and name.count("/") == 3 and name.endswith((".service", ".timer", ".socket", ".path")):
            units.add(Path(name).name)
        count += 1
    # A missing marker fences even an accidental boot of this offline filesystem.
    for unit in units:
        dropin = private_dir(target / "etc/systemd/system" / (unit + ".d"))
        (dropin / "00-disaster-recovery-fence.conf").write_text(
            "[Unit]\nConditionPathExists=/var/lib/accurast-recovery/LIVE-RECONCILIATION-APPROVED\n")
    # Rebuild only links whose target is present inside the offline tree. Rewrite
    # absolute links as relative links so inspection cannot escape to this host.
    unresolved, links_restored, enabled_links_skipped = [], 0, 0
    for name, rec in manifest.get("symlinks", {}).items():
        relative(name)
        if ".wants/" in name or ".requires/" in name:
            enabled_links_skipped += 1
            continue
        target_name = rec["target"]
        require(isinstance(target_name, str) and target_name and "\\" not in target_name, "Invalid recorded symlink")
        absolute_target = posixpath.normpath(target_name if target_name.startswith("/") else
                                             posixpath.join("/" + posixpath.dirname(name), target_name))
        link = target.joinpath(*mapped(name).parts)
        resolved = target.joinpath(*mapped(absolute_target.lstrip("/")).parts)
        if link.exists() or link.is_symlink() or not resolved.exists():
            unresolved.append(name)
            continue
        private_dir(link.parent)
        os.symlink(os.path.relpath(resolved, link.parent), link)
        links_restored += 1
    control = private_dir(target / "var/lib/accurast-recovery")
    write_json(control / "migration-config.json", config)
    write_json(control / "staging-report.json", {"files_copied": count, "units_fenced": sorted(units),
        "source_manifest_sha256": sha(source / "manifest.json"), "source_platform": manifest.get("platform"),
        "staging_platform": platform.system(), "ownership_restored": args.preserve_ownership,
        "symlinks_restored": links_restored, "unresolved_symlinks": unresolved,
        "enablement_links_intentionally_omitted": enabled_links_skipped,
        "directory_metadata_records": len(manifest.get("directories", {})),
        "live_actions_allowed": False,
        "warnings": ["Path and domain references inside captured code/config require review before boot.",
                     "Create required Linux service users and dependencies from captured metadata before installation.",
                     "Do not create the live approval marker before old-controller fencing and fresh reconciliation."]})
    # Restore directory metadata last: private_dir deliberately uses 0700 while
    # copying. Do not follow any symlink while applying directory ownership.
    for name, rec in sorted(manifest.get("directories", {}).items(), key=lambda row: -len(row[0])):
        dest = target.joinpath(*mapped(name).parts)
        require(not dest.is_symlink(), "Directory metadata collides with symlink")
        require(all(not parent.is_symlink() for parent in dest.parents if parent != target and target in parent.parents),
                "Directory metadata has symlink parent")
        if not dest.exists():
            dest.mkdir(parents=True, mode=0o700)
        mode = rec.get("source_mode", 0o700)
        if isinstance(mode, str): mode = int(mode, 8)
        dest.chmod(mode & 0o777)
        if args.preserve_ownership:
            os.chown(dest, rec.get("source_uid", 0), rec.get("source_gid", 0))
    print(json.dumps({"offline_root": str(target), "files_copied": count, "units_fenced": len(units), "services_started": 0}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error) if isinstance(error, RecoveryError) else "Offline staging failed closed", file=sys.stderr)
        sys.exit(1)
