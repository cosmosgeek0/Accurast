import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/"scripts"))
from recover import RecoveryError,download_asset,read_manifest


def record(name,data):
    return {"name":name,"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data)}


class MultipartRecovery(unittest.TestCase):
    def fixture(self):
        pieces={"host.tar.gz.part-000":b"first-part-", "host.tar.gz.part-001":b"second-part"}
        artifact={**record("host.tar.gz",b"".join(pieces.values())),"kind":"snapshot","destination":"host",
                  "parts":[record(name,data)for name,data in pieces.items()]}
        return pieces,artifact,{"schema":2,"repository":"owner/Accurast","tag":"test","artifacts":[artifact]}
    def test_resume_parts_stream_join_and_full_cache(self):
        pieces,artifact,manifest=self.fixture()
        with tempfile.TemporaryDirectory()as temp:
            cache=Path(temp).resolve()
            first=next(iter(pieces));(cache/first).write_bytes(pieces[first])
            calls=[]
            def fetch(args,label):
                name=args[args.index("--pattern")+1];calls.append(name)
                (Path(args[args.index("--dir")+1])/name).write_bytes(pieces[name]);return b""
            with patch("recover.command",side_effect=fetch):
                full=download_asset(manifest,artifact,cache,offline=False)
            self.assertEqual(full.read_bytes(),b"".join(pieces.values()))
            self.assertEqual(calls,["host.tar.gz.part-001"])
            self.assertTrue(all((cache/name).exists()for name in pieces))
            with patch("recover.command")as no_download:
                self.assertEqual(download_asset(manifest,artifact,cache,offline=True),full)
                no_download.assert_not_called()
    def test_bad_part_or_full_hash_never_adopted_and_prior_files_retained(self):
        pieces,artifact,manifest=self.fixture()
        with tempfile.TemporaryDirectory()as temp:
            cache=Path(temp).resolve()
            for name,data in pieces.items():(cache/name).write_bytes(data)
            prior=cache/"host.tar.gz.part-001";prior.write_bytes(b"corrupted")
            with self.assertRaises(RecoveryError):download_asset(manifest,artifact,cache,offline=True)
            self.assertEqual(prior.read_bytes(),b"corrupted")
            self.assertFalse((cache/artifact["name"]).exists())
            prior.write_bytes(pieces[prior.name]);artifact["sha256"]="f"*64
            with self.assertRaises(RecoveryError):download_asset(manifest,artifact,cache,offline=True)
            self.assertFalse((cache/artifact["name"]).exists())
            self.assertTrue(all((cache/name).exists()for name in pieces))
    def test_manifest_rejects_part_paths_and_aggregate_size_mismatch(self):
        pieces,artifact,manifest=self.fixture()
        with tempfile.TemporaryDirectory()as temp:
            path=Path(temp)/"release.json";path.write_text(json.dumps(manifest))
            self.assertEqual(len(read_manifest(path)["artifacts"][0]["parts"]),2)
            artifact["parts"][0]["name"]="../escape";path.write_text(json.dumps(manifest))
            with self.assertRaises(RecoveryError):read_manifest(path)
            artifact["parts"][0]["name"]="valid-part";artifact["bytes"]+=1;path.write_text(json.dumps(manifest))
            with self.assertRaises(RecoveryError):read_manifest(path)


if __name__=="__main__":unittest.main()
