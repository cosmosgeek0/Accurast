import os
from pathlib import Path,PurePosixPath
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/"scripts"))
from recover import RecoveryError,restore_directory_metadata


class DirectoryModeRestoration(unittest.TestCase):
    def test_linux_chown_precedes_sgid_restore_and_mac_defers(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp).resolve();dest=root/"var/lib/telemetry";dest.mkdir(parents=True)
            record={"source_mode":0o2770,"source_uid":os.getuid(),"source_gid":os.getgid()}
            rows={"var/lib/telemetry":record}
            events=[]
            def chown_clears_sgid(path,uid,gid):
                events.append("chown")
                Path(path).chmod(Path(path).stat().st_mode&0o777)
            with patch("recover.platform.system",return_value="Linux"),patch("recover.os.geteuid",return_value=0),patch("recover.os.chown",side_effect=chown_clears_sgid):
                result=restore_directory_metadata(root,rows,PurePosixPath,True)
                self.assertEqual(dest.stat().st_mode&0o7777,0o2770)
                self.assertEqual(result["special_modes_restored"],1)
                # Simulate prepare-linux-root's later ownership pass and repeat.
                chown_clears_sgid(dest,record["source_uid"],record["source_gid"])
                restore_directory_metadata(root,rows,PurePosixPath,True)
                self.assertEqual(dest.stat().st_mode&0o7777,0o2770)
            self.assertGreaterEqual(len(events),2)
            with patch("recover.platform.system",return_value="Darwin"),patch("recover.os.chown")as chown:
                result=restore_directory_metadata(root,rows,PurePosixPath,False)
                self.assertEqual(dest.stat().st_mode&0o7777,0o770)
                self.assertEqual(result["special_modes_deferred"],1)
                self.assertEqual(result["special_modes_restored"],0)
                with self.assertRaises(RecoveryError):restore_directory_metadata(root,rows,PurePosixPath,True)
                chown.assert_not_called()


if __name__=="__main__":unittest.main()
