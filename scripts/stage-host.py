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
from recover import BASE, RecoveryError, private_dir, read_manifest, relative, require, restore_directory_metadata, sha, verify_tree, verify_host, write_json


def restore_symlinks(target, symlinks, mapped):
    unresolved, restored, enabled_skipped, pending = [], 0, 0, []
    for name, rec in symlinks.items():
        relative(name)
        if ".wants/" in name or ".requires/" in name:
            enabled_skipped += 1
            continue
        target_name = rec["target"]
        require(isinstance(target_name, str) and target_name and "\\" not in target_name, "Invalid recorded symlink")
        absolute_target = posixpath.normpath(target_name if target_name.startswith("/") else
                                             posixpath.join("/" + posixpath.dirname(name), target_name))
        link = target.joinpath(*mapped(name).parts)
        resolved = target.joinpath(*mapped(absolute_target.lstrip("/")).parts)
        pending.append((name, link, resolved))
    while pending:
        deferred, progress = [], 0
        for name, link, resolved in pending:
            if link.exists() or link.is_symlink():
                unresolved.append(name)
            elif not resolved.exists():
                deferred.append((name, link, resolved))
            else:
                private_dir(link.parent)
                os.symlink(os.path.relpath(resolved, link.parent), link)
                restored += 1; progress += 1
        if not progress:
            unresolved.extend(name for name, _, _ in deferred)
            break
        pending = deferred
    return unresolved, restored, enabled_skipped


def sqlite_sidecars(files, file_sources, backups):
    """Select exact sidecars only for explicitly transaction-backed SQLite bases."""
    require(isinstance(backups, list), "Invalid SQLite backup metadata")
    selected = {}
    for entry in backups:
        original = entry.get("path") if isinstance(entry, dict) else entry
        require(isinstance(original, str), "Invalid SQLite backup path")
        name = original.lstrip("/"); relative(name)
        require(name in files and name in file_sources, "Declared SQLite backup is missing")
        with (file_sources[name] / name).open("rb") as source:
            require(source.read(16) == b"SQLite format 3\x00", "Declared SQLite backup has no SQLite header")
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = name + suffix
            if sidecar in files: selected[sidecar] = name
    return selected


def fence_units(target, units):
    for unit in units:
        require(Path(unit).name == unit and unit.endswith((".service", ".timer", ".socket", ".path")), "Invalid fenced unit name")
        dropin = private_dir(target / "etc/systemd/system" / (unit + ".d"))
        (dropin / "00-disaster-recovery-fence.conf").write_text(
            "[Unit]\nConditionPathExists=/var/lib/accurast-recovery/LIVE-RECONCILIATION-APPROVED\n")


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--snapshot", required=True, help="Verified restored host directory")
    p.add_argument("--target-root", required=True, help="Empty offline directory or mounted replacement root; never /")
    p.add_argument("--config", required=True)
    p.add_argument("--supplement", action="append", default=[], help="Verified additional host runtime tree; only exact-identical overlaps accepted")
    p.add_argument("--artifact-work", help="Restore work directory containing verified immutable image assets")
    p.add_argument("--release-manifest", default=str(BASE / "release-assets.json"))
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
    source_hash = sha(source / "manifest.json")
    file_sources = {name: source for name in manifest["files"]}
    supplements = []
    for value in args.supplement:
        extra = Path(value).resolve()
        require((extra / ".isolation.json").is_file(), "Restore supplement before staging")
        extra_manifest = json.loads((extra / "manifest.json").read_text())
        verify_tree(extra, extra_manifest)
        for name, rec in extra_manifest["files"].items():
            if name in manifest["files"]:
                require(rec["sha256"] == manifest["files"][name]["sha256"], "Supplement changes an authoritative file; explicit reconciliation required")
            else:
                manifest["files"][name] = rec
                file_sources[name] = extra
        for category in ("directories", "symlinks"):
            current = manifest.setdefault(category, {})
            for name, rec in extra_manifest.get(category, {}).items():
                if category == "symlinks" and name in current:
                    require(current[name]["target"] == rec["target"], "Supplement changes symlink target")
                current.setdefault(name, rec)
        for database in extra_manifest.get("sqlite_backups", []):
            if database not in manifest.setdefault("sqlite_backups", []):
                manifest["sqlite_backups"].append(database)
        supplements.append({"manifest_sha256": sha(extra / "manifest.json"), "files": len(extra_manifest["files"])})
    config = json.loads(Path(args.config).read_text())
    require(config.get("controller_mode") == "disabled-until-reconciled", "Controller mode must remain disabled")
    require(not args.preserve_ownership or os.geteuid() == 0, "Root required to restore ownership")
    require(not args.preserve_ownership or platform.system() == "Linux", "Original numeric ownership is restored only on Linux")
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
    sidecars = sqlite_sidecars(manifest["files"], file_sources, manifest.get("sqlite_backups", []))
    quarantined = []
    for name, rec in manifest["files"].items():
        if name.startswith("metadata/"):
            continue
        dest_rel = (relative("var/lib/accurast-recovery/forensic-sqlite-sidecars/" + name)
                    if name in sidecars else mapped(name))
        require(str(dest_rel) not in mapped_names, "Path mapping collision")
        mapped_names.add(str(dest_rel))
        dest = target.joinpath(*dest_rel.parts)
        private_dir(dest.parent)
        shutil.copyfile(file_sources[name] / name, dest)
        mode = rec.get("source_mode", 0o600)
        if isinstance(mode, str): mode = int(mode, 8)
        dest.chmod(0o600 if name in sidecars else mode & 0o777)  # never restore file setuid/setgid
        if args.preserve_ownership and name not in sidecars:
            os.chown(dest, rec.get("source_uid", 0), rec.get("source_gid", 0))
        if name in sidecars:
            require(sha(dest) == rec["sha256"], "Forensic SQLite sidecar copy differs from archive")
            quarantined.append({"original_path":name, "mapped_original_path":str(mapped(name)),
                "database_path":sidecars[name], "quarantine_path":str(dest_rel),
                "sha256":rec["sha256"], "bytes":rec["bytes"], "source_mode":mode,
                "source_uid":rec.get("source_uid",0), "source_gid":rec.get("source_gid",0)})
        if name.startswith("etc/systemd/system/") and name.count("/") == 3 and name.endswith((".service", ".timer", ".socket", ".path")):
            units.add(Path(name).name)
        count += 1
    # A missing marker fences even an accidental boot of this offline filesystem.
    for name, rec in manifest.get("symlinks", {}).items():
        if name.startswith("etc/systemd/system/") and name.count("/") == 3 and name.endswith((".service", ".timer", ".socket", ".path")):
            units.add(Path(name).name)
    fence_units(target, units)
    # Rebuild only links whose target is present inside the offline tree. Rewrite
    # absolute links as relative links so inspection cannot escape to this host.
    unresolved, links_restored, enabled_links_skipped = restore_symlinks(target, manifest.get("symlinks", {}), mapped)
    for row in quarantined:
        original_target = target / row["mapped_original_path"]
        require(not original_target.exists() and not original_target.is_symlink(), "Quarantined SQLite sidecar was recreated beside a database")
    images = []
    if args.artifact_work:
        release = read_manifest(args.release_manifest)
        artifact_work = Path(args.artifact_work).resolve()
        image_dir = config["image_directory"]
        require(image_dir.startswith("/"), "Image directory must be absolute")
        image_target = target.joinpath(*relative(image_dir.lstrip("/")).parts)
        private_dir(image_target)
        for artifact in release["artifacts"]:
            if artifact["kind"] != "immutable": continue
            restored = artifact_work / "restored" / artifact["destination"]
            proof = json.loads((artifact_work / ("proof-" + artifact["name"] + ".json")).read_text())
            require(proof["sha256"] == artifact["sha256"] and restored.is_file() and
                    not restored.is_symlink() and sha(restored) == artifact["sha256"], "Immutable image restore proof mismatch")
            dest = image_target / Path(artifact["destination"]).name
            if dest.exists():
                require(dest.is_file() and not dest.is_symlink() and sha(dest) == artifact["sha256"], "Image destination conflicts with captured content")
            else:
                shutil.copyfile(restored, dest); dest.chmod(0o600)
            images.append({"name": dest.name, "sha256": artifact["sha256"], "path": str(dest.relative_to(target))})
    control = private_dir(target / "var/lib/accurast-recovery")
    write_json(control / "migration-config.json", config)
    # Final ownership precedes mode restoration so SGID inheritance survives.
    directory_permissions = restore_directory_metadata(target, manifest.get("directories", {}), mapped, args.preserve_ownership)
    write_json(control / "staging-report.json", {"files_copied": count, "units_fenced": sorted(units),
        "source_manifest_sha256": source_hash, "source_platform": manifest.get("platform"),
        "supplement_manifests": supplements, "immutable_images": images,
        "sqlite_backups": manifest.get("sqlite_backups", []), "sqlite_sidecar_quarantine":quarantined,
        "required_uids": sorted({rec.get("source_uid", 0) for rec in manifest["files"].values()}),
        "required_gids": sorted({rec.get("source_gid", 0) for rec in manifest["files"].values()}),
        "staging_platform": platform.system(), "ownership_restored": args.preserve_ownership,
        "symlinks_restored": links_restored, "unresolved_symlinks": unresolved,
        "enablement_links_intentionally_omitted": enabled_links_skipped,
        "directory_metadata_records": len(manifest.get("directories", {})),
        "directory_permissions": directory_permissions,
        "live_actions_allowed": False,
        "warnings": ["Path and domain references inside captured code/config require review before boot.",
                     "Create required Linux service users and dependencies from captured metadata before installation.",
                     "Do not create the live approval marker before old-controller fencing and fresh reconciliation."]})
    print(json.dumps({"offline_root": str(target), "files_copied": count, "units_fenced": len(units), "services_started": 0}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error) if isinstance(error, RecoveryError) else "Offline staging failed closed", file=sys.stderr)
        sys.exit(1)
