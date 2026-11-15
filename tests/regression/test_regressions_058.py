"""Regression tests for FileGuard 0.5.8 (found in the v0.5.7 fresh-install test)."""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

BACKEND = Path(os.environ.get("FG_BACKEND", Path(__file__).resolve().parents[2] / "backend"))
sys.path.insert(0, str(BACKEND))


class SharedClamdOptOut(unittest.TestCase):
    def test_no_shared_clamd_is_honoured_by_the_scanner(self):
        try:
            from fileguard import scanners
        except ImportError as e:  # engine deps missing
            self.skipTest(str(e))
        pinged = []
        with mock.patch.object(scanners, "_ping", side_effect=lambda c: pinged.append(c) or c in scanners._SHARED_CONFS), \
             mock.patch.object(scanners.config, "CLAMD_CONF", "/nonexistent/clamav/clamd.conf"):
            with mock.patch.dict(os.environ, {"FILEGUARD_NO_SHARED_CLAMD": "1"}):
                self.assertIsNone(scanners.clamd_conf())
                self.assertEqual(pinged, ["/nonexistent/clamav/clamd.conf"])
            with mock.patch.dict(os.environ, {"FILEGUARD_NO_SHARED_CLAMD": "0"}):
                self.assertEqual(scanners.clamd_conf(), scanners._SHARED_CONFS[0])


if __name__ == "__main__":
    unittest.main()
