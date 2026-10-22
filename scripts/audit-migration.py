#!/usr/bin/env python3
"""Write a private, read-only migration report without printing config values."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).parent))
from recover import RecoveryError, require, relative, sha, snapshot_file, write_json


def audit(snapshot, target, config):
    snapshot, target = Path(snapshot).resolve(), Path(target).resolve()
    require(target != Path("/"), "Live root is forbidden")
    manifest = json.loads((snapshot / "manifest.json").read_text())
    staged = json.loads((target / "var/lib/accurast-recovery/staging-report.json").read_text())
    require(staged["source_manifest_sha256"] == sha(snapshot / "manifest.json"), "Staging manifest mismatch")
    units = json.loads(snapshot_file(snapshot, "metadata/systemd.json", manifest).read_text())
    mappings, overrides = config.get("source_path_mapping", {}), config.get("domain_overrides", {})
    def mapped(name):
        for before in sorted(mappings, key=len, reverse=True):
            if name == before or name.startswith(before.rstrip("/") + "/"):
                return mappings[before].rstrip("/") + name[len(before):]
        return name
    def present(name):
        if name == "/": return True
        relative(name.lstrip("/"))
        path = target / mapped(name).lstrip("/")
        return path.exists() and (path.resolve() == target or target in path.resolve().parents)
    missing, binds, unit_rows = [], [], []
    for unit, props in units.items():
        refs = []
        for key in ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload"):
            refs.extend((key, p) for p in re.findall(r"(?:^|[ ;{])path=(/[^ ;}]+)", props.get(key, "")))
        work = props.get("WorkingDirectory", "").lstrip("-")
        if work.startswith("/"): refs.append(("WorkingDirectory", work))
        for field in ("BindPaths", "BindReadOnlyPaths"):
            for value in props.get(field, "").split():
                parts = value.lstrip("-").split(":")
                if not parts or not parts[0].startswith("/"): continue
                src, dst = parts[0], parts[1] if len(parts) > 1 else parts[0]
                refs.append((field, src)); binds.append({"unit": unit, "source": src, "target": dst, "source_present": present(src)})
        for field, value in refs:
            if "%" in value or not present(value):
                missing.append({"unit": unit, "field": field, "path": value})
        fence = target / "etc/systemd/system" / (unit + ".d") / "00-disaster-recovery-fence.conf"
        unit_rows.append({"unit": unit, "fence_present": fence.is_file(), "references_checked": len(refs)})
    domain_occurrences, path_occurrences = {}, {}
    scanned = 0
    for name, rec in manifest["files"].items():
        p = Path(name)
        # Source/config inspection excludes identity state and dependency copies.
        if p.suffix not in (".py", ".mjs", ".js", ".sh", ".service", ".conf", ".yaml", ".yml"):
            continue
        if any(part in ("node_modules", "vault", "private") for part in p.parts) or rec["bytes"] > 5 * 1024 * 1024:
            continue
        text = (snapshot / name).read_text(errors="replace"); scanned += 1
        for old in mappings:
            if old in text: path_occurrences.setdefault(old, []).append(name)
        # Report hostname only, never URL paths, credentials, queries or line text.
        for url in re.findall(r"https?://[^\s\"'<>]+", text):
            try: hostname = urlsplit(url).hostname
            except ValueError: continue
            if hostname and re.fullmatch(r"[A-Za-z0-9.-]+", hostname):
                domain_occurrences.setdefault(hostname.lower(), set()).add(name)
    domains = [{"hostname": host, "source_files": sorted(names), "configured_replacement": overrides.get(host)}
               for host, names in sorted(domain_occurrences.items())]
    image_path = config.get("image_directory", "")
    require(image_path.startswith("/"), "Image directory must be absolute")
    quarantined = staged.get("sqlite_sidecar_quarantine", [])
    for row in quarantined:
        original = target / str(relative(row["mapped_original_path"]))
        forensic = target / str(relative(row["quarantine_path"]))
        require(not original.exists() and not original.is_symlink(), "SQLite sidecar reappeared beside coherent backup")
        require(forensic.is_file() and not forensic.is_symlink() and sha(forensic) == row["sha256"], "Forensic SQLite sidecar proof mismatch")
    return {"source_files_scanned": scanned, "unit_checks": unit_rows, "missing_unit_references": missing,
            "bind_mounts_to_recreate_by_preserved_units": binds, "source_path_references_requiring_review": path_occurrences,
            "hostname_references": domains, "configured_image_directory": image_path,
            "image_directory_present": present(image_path), "references_rewritten": False,
            "sqlite_sidecars_quarantined": quarantined,
            "services_started": 0, "live_actions_allowed": False,
            "limitations": ["References generated at runtime and provider-side acceptance need live validation.",
                            "Missing OS executables may be supplied by the pinned package plan; packages are not installed by this audit.",
                            "Matching source files do not prove DNS ownership, routing or image HTTP delivery."]}


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--snapshot", required=True)
    p.add_argument("--target-root", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    report = audit(args.snapshot, args.target_root, json.loads(Path(args.config).read_text()))
    require(not Path(args.out).exists(), "Audit output already exists")
    write_json(args.out, report)
    print(json.dumps({"report": args.out, "units_checked": len(report["unit_checks"]),
                      "missing_unit_references": len(report["missing_unit_references"]),
                      "hostname_references": len(report["hostname_references"]), "live_actions_allowed": False}))


if __name__ == "__main__":
    try: main()
    except Exception as error:
        print(str(error) if isinstance(error, RecoveryError) else "Migration audit failed closed", file=sys.stderr)
        sys.exit(1)
