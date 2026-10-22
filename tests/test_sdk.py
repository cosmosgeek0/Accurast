import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/"scripts"))
from recover import RecoveryError
spec=importlib.util.spec_from_file_location("install_sdk",BASE/"scripts/install-owner-sdk.py")
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)
PREFIX="local/project/archive/legacy-acurast-20260928"


def tree(root,files):
    root.mkdir()
    records={}
    for name,data in files.items():
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
        records[name]={"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"source_mode":0o755 if name.endswith("/esbuild")else 0o600}
    (root/"manifest.json").write_text(json.dumps({"files":records}))
    (root/".isolation.json").write_text('{}')


class OwnerSdkSafety(unittest.TestCase):
    def test_new_tree_platform_selection_links_and_originals_preserved(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp).resolve();base=root/"owner";sdk=root/"sdk";out=root/"assembled"
            lock=b'{"lockfileVersion":3}'
            native=b'synthetic-ELF-linux-binary'
            proof={"preservation_source_prefix":PREFIX,"package_lock_sha256":hashlib.sha256(lock).hexdigest(),
                   "required_locked_packages_missing":[],"version_mismatches":[],"supported_platforms":["linux-x64"],
                   "added_platform_packages":[{"supported_platform":"linux-x64","binary_sha256":hashlib.sha256(native).hexdigest()}]}
            tree(base,{PREFIX+"/package-lock.json":lock,"local/project/operations/receipt.json":b'{"finalized":true}'})
            tree(sdk,{PREFIX+"/package-lock.json":lock,PREFIX+"/package.json":b'{}',
                      PREFIX+"/node_modules/@esbuild/linux-x64/bin/esbuild":native,
                      PREFIX+"/node_modules/esbuild/bin/esbuild":b'synthetic-original-MachO',
                      PREFIX+"/node_modules/.bin/esbuild":b'synthetic-original-MachO',
                      "metadata/dependency-proof.json":json.dumps(proof).encode()})
            result=installer.install(base,sdk,out,"linux-x64")
            self.assertEqual(result["programs_executed"],0)
            self.assertEqual((out/PREFIX/"node_modules/.bin/esbuild").resolve(),out/PREFIX/"node_modules/@esbuild/linux-x64/bin/esbuild")
            self.assertEqual((out/"local/project/node_modules").resolve(),out/PREFIX/"node_modules")
            self.assertEqual((out/"local/project/operations/platform-pilots/node_modules").resolve(),out/PREFIX/"node_modules")
            self.assertEqual((sdk/PREFIX/"node_modules/esbuild/bin/esbuild").read_bytes(),b'synthetic-original-MachO')
            with self.assertRaises(RecoveryError):installer.install(base,sdk,out,"linux-x64")
            with self.assertRaises(RecoveryError):installer.install(base,sdk,root/"unsupported","linux-arm64")
            self.assertFalse((root/"unsupported").exists())


if __name__=="__main__":unittest.main()
