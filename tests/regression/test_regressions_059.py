"""Regression tests for the release after 0.5.8: clamd must not keep running from an old .prev-* tree.

After an update (including a same-version reinstall) install.sh moves the old tree, vendor/
included, to $DIR/.prev-<ts>; the running clamd's binary then lives there (or is deleted when
the next install removes .prev-*). start_clamd.sh only compared versions, so a same-version
clamd was never restarted. These tests drive the real scripts against a fake, inert
clamd/clamdscan built in a temp dir (no sample is executed; no real clamd is touched).
"""
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

BACKEND = Path(os.environ.get("FG_BACKEND", Path(__file__).resolve().parents[2] / "backend"))

FAKE_CLAMD_C = r"""
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
static char sock[512], pidf[512];
static void bye(int s) { (void)s; unlink(sock); unlink(pidf); _exit(0); }
int main(int argc, char **argv) {
  const char *ver = getenv("FAKE_CLAMAV_VER"); if (!ver) ver = "1.4.6";
  const char *conf = NULL;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--version")) { printf("ClamAV %s/27000/Thu Jan  1 00:00:00 2026\n", ver); return 0; }
    if (!strncmp(argv[i], "--config-file=", 14)) conf = argv[i] + 14;
  }
  FILE *f = conf ? fopen(conf, "r") : NULL; if (!f) return 1;
  char line[1024];
  while (fgets(line, sizeof line, f)) {
    line[strcspn(line, "\n")] = 0;
    if (!strncmp(line, "LocalSocket ", 12)) snprintf(sock, sizeof sock, "%s", line + 12);
    if (!strncmp(line, "PidFile ", 8)) snprintf(pidf, sizeof pidf, "%s", line + 8);
  }
  fclose(f);
  if (fork() > 0) return 0;
  setsid();
  int dn = open("/dev/null", O_RDWR); dup2(dn, 0); dup2(dn, 1); dup2(dn, 2);   /* daemonize like clamd */
  signal(SIGTERM, bye);
  int s = socket(AF_UNIX, SOCK_STREAM, 0); struct sockaddr_un a = {0}; a.sun_family = AF_UNIX;
  snprintf(a.sun_path, sizeof a.sun_path, "%s", sock); unlink(sock);
  if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 1)) return 1;
  char vf[600]; snprintf(vf, sizeof vf, "%s.ver", pidf);
  FILE *v = fopen(vf, "w"); if (v) { fprintf(v, "%s\n", ver); fclose(v); }
  FILE *p = fopen(pidf, "w"); if (p) { fprintf(p, "%d\n", getpid()); fclose(p); }
  for (int i = 0; i < 600; i++) sleep(1);   /* self-terminates after 10 min at the latest */
  bye(0); return 0;
}
"""

FAKE_CLAMDSCAN = r"""#!/usr/bin/env bash
conf=""; ping=0; ver=0
for a in "$@"; do case "$a" in --config-file=*) conf="${a#--config-file=}" ;; --ping) ping=1 ;; --version) ver=1 ;; esac; done
sock="$(sed -n 's/^LocalSocket //p' "$conf" 2>/dev/null)"; pidf="$(sed -n 's/^PidFile //p' "$conf" 2>/dev/null)"
alive() { [ -S "$sock" ] && [ -f "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; }
if [ "$ver" = 1 ]; then alive && echo "ClamAV $(cat "$pidf.ver")/27000" && exit 0; exit 2; fi
if [ "$ping" = 1 ]; then alive && exit 0; exit 1; fi
exit 2
"""


def _shell_function(path, name):
    """The text of one top-level bash function `name() {...}` from a script (ends at a line '}')."""
    m = re.search(rf"^{name}\(\) \{{.*?^\}}\n", Path(path).read_text(), re.S | re.M)
    assert m, f"{name} not found in {path}"
    return m.group(0)


@unittest.skipUnless(shutil.which("cc") and Path("/proc/self/exe").exists(), "needs cc and /proc")
class ClamdNotLeftInPrevTree(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fg-clamd-test-")).resolve()
        self.root = self.tmp / "fileguard"
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "clamav").mkdir()
        shutil.copy(BACKEND / "scripts" / "start_clamd.sh", self.root / "scripts" / "start_clamd.sh")
        shutil.copy(BACKEND / "clamav" / "clamd.conf.in", self.root / "clamav" / "clamd.conf.in")
        src = self.tmp / "fake_clamd.c"
        src.write_text(FAKE_CLAMD_C)
        self.fake_bin = self.tmp / "build" / "clamd"
        self.fake_bin.parent.mkdir()
        subprocess.run(["cc", "-O0", "-o", str(self.fake_bin), str(src)], check=True)
        self.install_vendor(self.root / "vendor")
        (self.root / "data" / "clamav-db").mkdir(parents=True)
        (self.root / "data" / "clamav-db" / "main.cvd").write_text("fake")
        self.pids = set()

    def tearDown(self):
        for pid in self.pids | {self.pid()}:
            if pid:
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def install_vendor(self, vendor):
        v = vendor / "clamav"
        (v / "sbin").mkdir(parents=True)
        (v / "bin").mkdir()
        (v / "lib").mkdir()
        shutil.copy(self.fake_bin, v / "sbin" / "clamd")
        (v / "bin" / "clamdscan").write_text(FAKE_CLAMDSCAN)
        os.chmod(v / "bin" / "clamdscan", 0o755)

    def start(self, **env):
        e = dict(os.environ, FILEGUARD_NO_SHARED_CLAMD="1", FILEGUARD_DATA=str(self.root / "data"), **env)
        e.pop("FILEGUARD_CLAMAV_DB", None)
        r = subprocess.run(["bash", str(self.root / "scripts" / "start_clamd.sh")], env=e,
                           capture_output=True, text=True, timeout=120)
        pid = self.pid()
        if pid:
            self.pids.add(pid)
        return r

    def pid(self):
        try:
            return int((self.root / "run" / "clamd.pid").read_text().strip())
        except (OSError, ValueError):
            return None

    @staticmethod
    def exe(pid):
        return os.readlink(f"/proc/{pid}/exe")

    @staticmethod
    def alive(pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False

    def swap(self, ts):
        """What install.sh step 6 does to vendor/: old tree to .prev-*, new one hard-linked in."""
        prev = self.root / f".prev-{ts}"
        prev.mkdir()
        (self.root / "vendor").rename(prev / "vendor")
        shutil.copytree(prev / "vendor", self.root / "vendor", copy_function=os.link)
        return prev

    def start_foreign(self, binary, ver="1.4.6"):
        """Start a fake clamd from `binary` on THIS install's socket/pid file."""
        (self.root / "run").mkdir(exist_ok=True)
        conf = self.root / "clamav" / "clamd.conf"
        conf.write_text((self.root / "clamav" / "clamd.conf.in").read_text()
                        .replace("@FILEGUARD_DIR@", str(self.root)).replace("@CLAMAV_DB@", "/nonexistent"))
        subprocess.run([str(binary), f"--config-file={conf}"], env=dict(os.environ, FAKE_CLAMAV_VER=ver),
                       check=True, timeout=10)
        for _ in range(50):
            if self.pid():
                break
            time.sleep(0.1)
        self.pids.add(self.pid())
        return self.pid()

    def own_check(self, script, name, pid):
        """Run the lock self-heal predicate `name` from install.sh / bootstrap.sh for `pid`."""
        fn = _shell_function(BACKEND / script, name)
        r = subprocess.run(["bash", "-c", f'DIR="$1"\n{fn}\n{name} "$2"', "_", str(self.root), str(pid)],
                           capture_output=True, text=True, timeout=10)
        return r.returncode == 0

    def test_same_version_update_restarts_clamd_from_current_tree(self):
        r = self.start()
        self.assertEqual(r.returncode, 0, r.stderr)
        first = self.pid()
        self.assertEqual(self.exe(first), str(self.root / "vendor/clamav/sbin/clamd"))
        prev = self.swap(1)
        self.assertTrue(self.exe(first).startswith(str(prev)))   # the bug's precondition
        r = self.start()
        self.assertEqual(r.returncode, 0, r.stderr)
        second = self.pid()
        self.assertNotEqual(first, second)
        self.assertFalse(self.alive(first))
        self.assertEqual(self.exe(second), str(self.root / "vendor/clamav/sbin/clamd"))
        self.start()   # an up-to-date clamd is left alone
        self.assertEqual(self.pid(), second)

    def test_clamd_running_from_deleted_prev_tree_is_restarted(self):
        self.start()
        first = self.pid()
        prev = self.swap(2)
        shutil.rmtree(prev)   # next install's `rm -rf .prev-*`
        self.assertTrue(self.exe(first).endswith("(deleted)"))
        r = self.start()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.alive(first))
        self.assertEqual(self.exe(self.pid()), str(self.root / "vendor/clamav/sbin/clamd"))

    def test_foreign_clamd_is_never_stopped(self):
        # a clamd binary outside this install dir, on our socket and pid file, older version
        foreign = self.start_foreign(self.fake_bin, ver="1.0.0")
        r = self.start()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("not this install's own clamd", r.stderr)
        self.assertTrue(self.alive(foreign))
        self.assertEqual(self.pid(), foreign)

    def test_lock_self_heal_recognises_prev_and_deleted_trees(self):
        self.start()
        pid = self.pid()
        for script, name in (("install.sh", "is_own_clamd"), ("bootstrap.sh", "own_clamd")):
            self.assertTrue(self.own_check(script, name, pid), f"{script}: current tree")
        prev = self.swap(3)
        for script, name in (("install.sh", "is_own_clamd"), ("bootstrap.sh", "own_clamd")):
            self.assertTrue(self.own_check(script, name, pid), f"{script}: .prev tree")
        shutil.rmtree(prev)
        for script, name in (("install.sh", "is_own_clamd"), ("bootstrap.sh", "own_clamd")):
            self.assertTrue(self.own_check(script, name, pid), f"{script}: deleted")
        (self.root / "run" / "clamd.pid").write_text("1\n")   # pid mismatch -> not ours
        for script, name in (("install.sh", "is_own_clamd"), ("bootstrap.sh", "own_clamd")):
            self.assertFalse(self.own_check(script, name, pid), f"{script}: pid mismatch")

    def test_lock_self_heal_rejects_clamd_outside_install_dir(self):
        foreign = self.start_foreign(self.fake_bin)   # pid file matches, binary is elsewhere
        for script, name in (("install.sh", "is_own_clamd"), ("bootstrap.sh", "own_clamd")):
            self.assertFalse(self.own_check(script, name, foreign), script)


if __name__ == "__main__":
    unittest.main()
