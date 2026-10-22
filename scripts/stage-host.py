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
from recover import BASE, RecoveryError, private_dir, read_manifest, relative, require, sha, verify_tree, verify_host, write_json


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
        supplements.append({"manifest_sha256": sha(extra / "manifest.json"), "files": len(extra_manifest["files"])})
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
        shutil.copyfile(file_sources[name] / name, dest)
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
    unresolved, links_restored, enabled_links_skipped = restore_symlinks(target, manifest.get("symlinks", {}), mapped)
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
    write_json(control / "staging-report.json", {"files_copied": count, "units_fenced": sorted(units),
        "source_manifest_sha256": source_hash, "source_platform": manifest.get("platform"),
        "supplement_manifests": supplements, "immutable_images": images,
        "required_uids": sorted({rec.get("source_uid", 0) for rec in manifest["files"].values()}),
        "required_gids": sorted({rec.get("source_gid", 0) for rec in manifest["files"].values()}),
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
