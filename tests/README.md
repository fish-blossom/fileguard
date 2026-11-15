# FileGuard tests

Nothing in this directory is shipped: the release tarball is built from `backend/` only.
Nothing here is ever executed as a sample; FileGuard is a static scanner.

| Path | What |
|---|---|
| `regression/` | Regression tests for fixed bugs (`test_regressions_055.py`, `test_regressions_056.py`). Run: `python -m unittest discover -s tests/regression` with the engine's dependencies installed (CI: `.github/workflows/tests.yml`). Tests that need an optional tool (for example `yara-python`) skip when it is missing. |
| `run_batch.py` | Submits every sample of a batch to an installed engine (always a temporary copy) and writes `results.json` + a comparison against the batch README. |
| `samples/<batch>/` | A generated batch: per scenario one clean and one suspicious sample, random number and kind of planted behaviours. Its `README.md` is the ground truth (expected findings and verdicts). |
| `samples/_generator/` | The generator (`gen.py`, `readme.py`, `vba.py`). `FG_SEED=<seed> FG_OUT=<dir> python gen.py` reproduces a batch's structure. |

**All "suspicious" samples are fabricated and inert.** Suspicious code sits after `exit 0` / `return` /
`WScript.Quit` or in functions that are never called; every network address is reserved
(`*.invalid`, 192.0.2.x, 198.51.100.x, 203.0.113.x); PE entry points are `xor eax,eax; ret`. Some
batches contain the standard EICAR antivirus test string, so local antivirus may flag this directory;
that is expected.

`backend/examples/` holds two of these inert samples (byte-identical copies, checked by
`test_regressions_056.py`) for the bot's `fg demo 1|2` example tests.
