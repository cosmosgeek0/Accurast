import importlib.util
from pathlib import Path, PurePosixPath
import sys
import tempfile
import unittest

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/"scripts"))
spec=importlib.util.spec_from_file_location("stage_host",BASE/"scripts/stage-host.py")
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)


class StagingSymlinkChains(unittest.TestCase):
    def test_later_intermediate_link_resolved_without_creating_os_mask(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary).resolve();library=root/"opt/runtime/library.actual"
            library.parent.mkdir(parents=True);library.write_bytes(b"preserved-binary")
            links={"opt/runtime/library.so":{"target":"library.so.1"},
                   "opt/runtime/library.so.1":{"target":"library.actual"},
                   "etc/systemd/system/held.service":{"target":"/dev/null"}}
            unresolved,count,skipped=stage.restore_symlinks(root,links,PurePosixPath)
            self.assertEqual(count,2);self.assertEqual(skipped,0)
            self.assertEqual((root/"opt/runtime/library.so").read_bytes(),b"preserved-binary")
            self.assertEqual((root/"opt/runtime/library.so").resolve(),library)
            self.assertEqual(unresolved,["etc/systemd/system/held.service"])
            self.assertFalse((root/"etc/systemd/system/held.service").is_symlink())
    def test_service_alias_receives_missing_marker_fence(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary).resolve();source=root/"opt/runtime/worker.service"
            source.parent.mkdir(parents=True);source.write_text("[Service]\nExecStart=/bin/false\n")
            stage.fence_units(root,{"alias.service"})
            stage.restore_symlinks(root,{"etc/systemd/system/alias.service":{"target":"/opt/runtime/worker.service"}},PurePosixPath)
            self.assertTrue((root/"etc/systemd/system/alias.service").is_symlink())
            self.assertIn("ConditionPathExists=",(root/"etc/systemd/system/alias.service.d/00-disaster-recovery-fence.conf").read_text())
            self.assertFalse((root/"var/lib/accurast-recovery/LIVE-RECONCILIATION-APPROVED").exists())


if __name__=="__main__":unittest.main()
