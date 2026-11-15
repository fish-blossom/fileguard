"""bootstrap.sh removes the getting-started download dir /tmp/fileguard-src.XXXXXX, and nothing else."""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

BACKEND = Path(os.environ.get("FG_BACKEND", Path(__file__).resolve().parents[2] / "backend"))
BOOT = BACKEND / "bootstrap.sh"


def _fn(name):
    m = re.search(rf"^{name}\(\) \{{.*?^\}}\n", BOOT.read_text(), re.S | re.M)
    assert m, name
    return m.group(0)


@unittest.skipUnless(Path("/tmp").is_dir() and os.path.realpath("/tmp") == "/tmp", "needs a real /tmp")
class BootstrapSourceCleanup(unittest.TestCase):
    def setUp(self):
        self.made = []

    def tearDown(self):
        for p in self.made:
            if os.path.islink(p):
                os.unlink(p)
            else:
                shutil.rmtree(p, ignore_errors=True)

    def cleanup(self, self_dir):
        subprocess.run(["bash", "-c", f'SELF_DIR="$1"\n{_fn("cleanup_src")}\ncleanup_src', "_", str(self_dir)],
                       check=True, timeout=10)

    def src_dir(self, prefix="/tmp/fileguard-src."):
        d = Path(tempfile.mkdtemp(prefix=os.path.basename(prefix), dir=os.path.dirname(prefix)))
        self.made.append(str(d))
        (d / "fileguard").mkdir()
        (d / "fileguard" / "bootstrap.sh").write_text("# copy\n")
        return d

    def test_getting_started_dir_is_removed(self):
        d = Path(subprocess.run(["mktemp", "-d", "/tmp/fileguard-src.XXXXXX"], capture_output=True, text=True,
                                check=True).stdout.strip())
        self.made.append(str(d))
        (d / "fileguard").mkdir()
        self.cleanup(d / "fileguard")
        self.assertFalse(d.exists())

    def test_other_dirs_are_kept(self):
        wrong_shape = Path("/tmp/fileguard-src.abc")          # not the 6-char mktemp suffix
        wrong_shape.mkdir(exist_ok=True); self.made.append(str(wrong_shape))
        (wrong_shape / "fileguard").mkdir(exist_ok=True)
        other = self.src_dir("/tmp/fg-other.")                  # other prefix
        nested = self.src_dir()                                 # script not directly in <dir>/fileguard
        (nested / "fileguard" / "sub").mkdir()
        for self_dir in (wrong_shape / "fileguard", other / "fileguard", nested / "fileguard" / "sub",
                         Path("/workspace/fileguard"), BACKEND):
            self.cleanup(self_dir)
        for d in (wrong_shape, other, nested):
            self.assertTrue(d.exists(), d)

    def test_symlinked_dir_is_kept(self):
        real = self.src_dir("/tmp/fg-real-target.")
        link = Path(subprocess.run(["mktemp", "-u", "/tmp/fileguard-src.XXXXXX"], capture_output=True, text=True,
                                   check=True).stdout.strip())
        os.symlink(real, link); self.made.append(str(link))
        self.cleanup(link / "fileguard")   # realpath resolves outside the pattern
        self.assertTrue(real.exists())
        self.assertTrue(link.is_symlink())

    def test_cleanup_only_after_a_usable_install(self):
        text = BOOT.read_text()
        calls = [m.start() for m in re.finditer(r"^\s*cleanup_src\s*$", text, re.M)]
        self.assertEqual(len(calls), 1)
        before = text[:calls[0]].rsplit("\n", 3)[-3:]
        self.assertTrue(any('"usable") is True' in line and "$rc -eq 0" in line for line in before), before)


if __name__ == "__main__":
    unittest.main()
