#!/usr/bin/env python3
"""Assemble owner-local base + pinned delta into a NEW private directory."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).parent))
from recover import BASE, RecoveryError, private_dir, read_manifest, relative, require, sha, verify_tree, write_json


def merge(base, delta, output, base_plaintext_sha256):
    base, delta, output = Path(base), Path(delta), Path(output)
    bm = json.loads((base / "manifest.json").read_text())
    dm = json.loads((delta / "manifest.json").read_text())
    verify_tree(base, bm); verify_tree(delta, dm)
    require(dm.get("base_artifact_plaintext_sha256") == base_plaintext_sha256, "Delta belongs to a different base artifact")
    require(not dm.get("deleted_files"), "Delta deletion requires separate review; no files deleted")
    for name, record in dm["files"].items():
        require("prior_sha256" in record, "Delta lacks prior-file proof")
        prior = bm["files"].get(name)
        require((prior["sha256"] if prior else None) == record["prior_sha256"], "Delta prior-file hash mismatch")
    resolved = output.absolute()
    require(resolved != base.resolve() and resolved != delta.resolve() and
            base.resolve() not in resolved.parents and delta.resolve() not in resolved.parents,
            "Merged result must be separate from both inputs")
    private_dir(output)
    require(not any(output.iterdir()), "Merged result directory must be empty")
    files = {**bm["files"], **dm["files"]}
    for name in files:
        source = delta if name in dm["files"] else base
        dest = output.joinpath(*relative(name).parts)
        private_dir(dest.parent)
        shutil.copyfile(source / name, dest)
        dest.chmod(0o600)
    result = {**bm, "files": files, "base_artifact_plaintext_sha256": base_plaintext_sha256,
              "delta_manifest_sha256": sha(delta / "manifest.json"), "assembled_from_verified_delta": True}
    write_json(output / "manifest.json", result)
    write_json(output / ".isolation.json", {"live_root": False, "services_started": 0, "transactions_signed": 0})
    verify_tree(output, result)
    return {"files_verified": len(files), "delta_files": len(dm["files"]), "source_inputs_modified": False}


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--work", required=True)
    p.add_argument("--manifest", default=str(BASE / "release-assets.json"))
    p.add_argument("--base", default="owner-local", help="Base destination from release manifest")
    p.add_argument("--delta", default="owner-local-delta", help="Delta destination from release manifest")
    p.add_argument("--output", required=True)
    args = p.parse_args()
    manifest = read_manifest(args.manifest)
    work = Path(args.work)
    roots = {}
    for label in (args.base, args.delta):
        matching = [a for a in manifest["artifacts"] if a["destination"] == label and a["kind"] == "local-state"]
        require(len(matching) == 1, "Base/delta missing from pinned release manifest")
        artifact = matching[0]
        root = work / "restored" / label
        proof = json.loads((work / ("proof-" + artifact["name"] + ".json")).read_text())
        require(proof["sha256"] == artifact["sha256"] and
                proof["member_manifest_sha256"] == sha(root / "manifest.json"), "Restoration proof mismatch")
        roots[label] = (root, artifact["sha256"])
    result = merge(roots[args.base][0], roots[args.delta][0], args.output, roots[args.base][1])
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error) if isinstance(error, RecoveryError) else "Local delta assembly failed closed", file=sys.stderr)
        sys.exit(1)
