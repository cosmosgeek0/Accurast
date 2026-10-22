#!/usr/bin/env python3
"""Assemble a NEW owner-local tree with preserved chain SDK; no fetch or execution."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import sys

sys.path.insert(0, str(Path(__file__).parent))
from recover import RecoveryError, private_dir, relative, require, sha, snapshot_file, verify_tree, write_json


def target_platform(value):
    if value != "auto": return value
    operating = {"Linux":"linux", "Darwin":"darwin"}.get(platform.system())
    machine = {"x86_64":"x64", "amd64":"x64", "arm64":"arm64", "aarch64":"arm64"}.get(platform.machine().lower())
    require(operating and machine, "Unsupported SDK target platform")
    return operating + "-" + machine


def install(owner_local, sdk, output, selected="auto"):
    base, sdk, output = Path(owner_local).resolve(), Path(sdk).resolve(), Path(output).absolute()
    require(output.resolve() != Path("/") and all(output.resolve() != p and p not in output.resolve().parents and output.resolve() not in p.parents for p in (base,sdk)),
            "SDK output must be new and independent of both source trees and live root")
    require(not output.exists(), "SDK output must not already exist")
    bm = json.loads((base / "manifest.json").read_text())
    sm = json.loads((sdk / "manifest.json").read_text())
    require((base / ".isolation.json").is_file() and (sdk / ".isolation.json").is_file(), "Restore both inputs in isolation before SDK assembly")
    verify_tree(base,bm); verify_tree(sdk,sm)
    proof = json.loads(snapshot_file(sdk,"metadata/dependency-proof.json",sm).read_text())
    require(not proof.get("required_locked_packages_missing") and not proof.get("version_mismatches"), "SDK dependency closure is incomplete")
    prefix = proof["preservation_source_prefix"]
    relative(prefix)
    require(prefix == "local/project/archive/legacy-acurast-20260928", "Unexpected SDK preservation prefix")
    chosen = target_platform(selected)
    require(chosen in proof["supported_platforms"], "Requested platform is not preserved in the SDK artifact")
    lock = prefix + "/package-lock.json"
    require(sha(sdk / lock) == proof["package_lock_sha256"], "SDK lockfile digest mismatch")
    native = prefix + "/node_modules/@esbuild/" + chosen + "/bin/esbuild"
    require(native in sm["files"], "Selected native esbuild binary missing")
    package_evidence = next((p for p in proof.get("added_platform_packages",[]) if p["supported_platform"] == chosen),None)
    if package_evidence:
        require(sm["files"][native]["sha256"] == package_evidence["binary_sha256"], "Native esbuild differs from preserved package proof")
    files = dict(bm["files"])
    sources = {name:base for name in files}
    for name, record in sm["files"].items():
        if name in files:
            require(files[name]["sha256"] == record["sha256"], "SDK conflicts with preserved owner-local content")
        files[name] = record; sources[name] = sdk
    link_names = [prefix + "/node_modules/esbuild/bin/esbuild", prefix + "/node_modules/.bin/esbuild",
                  "local/project/node_modules", "local/project/operations/platform-pilots/node_modules"]
    replaced = {name:files[name]["sha256"] for name in link_names if name in files}
    for name in link_names: files.pop(name,None)
    private_dir(output)
    for name, record in files.items():
        dest = output.joinpath(*relative(name).parts)
        private_dir(dest.parent)
        shutil.copyfile(sources[name]/name,dest)
        mode = record.get("source_mode",0o600)
        if isinstance(mode,str):mode=int(mode,8)
        # Restore SDK executable bits only; other recovered files remain private data.
        dest.chmod(0o700 if name.startswith(prefix + "/node_modules/") and mode & 0o111 else 0o600)
    links = {}
    for name in link_names:
        dest = output / name
        resolved = output / (native if name.endswith("/esbuild") else prefix + "/node_modules")
        require(resolved.exists() and not dest.exists(), "SDK symlink destination conflict")
        private_dir(dest.parent)
        link = os.path.relpath(resolved,dest.parent)
        os.symlink(link,dest)
        require(dest.resolve() == resolved.resolve() and output.resolve() in dest.resolve().parents, "SDK symlink escapes assembled tree")
        links[name] = {"target":link}
    require(os.access(output/native,os.X_OK), "Preserved native esbuild executable mode missing")
    result = {"format":"accurast-owner-local-sdk-v1","files":files,"symlinks":links,
              "base_manifest_sha256":sha(base/"manifest.json"),"sdk_manifest_sha256":sha(sdk/"manifest.json"),
              "sdk_platform":chosen,"replaced_platform_cli_original_hashes":replaced}
    write_json(output/"manifest.json",result)
    write_json(output/".isolation.json",{"live_root":False,"services_started":0,"transactions_signed":0})
    verify_tree(output,result)
    return {"files_verified":len(files),"symlinks_created":len(links),"sdk_platform":chosen,
            "native_esbuild_sha256":sha(output/native),"input_trees_modified":False,
            "network_fetches":0,"programs_executed":0,"transactions_signed":0}


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--owner-local",required=True,help="Verified base+delta assembled owner-local tree")
    p.add_argument("--sdk",required=True,help="Verified restored owner-sdk tree")
    p.add_argument("--output",required=True,help="Must not exist; neither input is changed")
    p.add_argument("--platform",default="auto",choices=("auto","linux-x64","linux-arm64","darwin-arm64"))
    args=p.parse_args()
    print(json.dumps(install(args.owner_local,args.sdk,args.output,args.platform)))


if __name__ == "__main__":
    try:main()
    except Exception as error:
        print(str(error) if isinstance(error,RecoveryError) else "Owner SDK assembly failed closed",file=sys.stderr)
        sys.exit(1)
