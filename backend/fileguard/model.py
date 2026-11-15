"""Shared data structures for the pipeline."""
from dataclasses import dataclass, field, asdict
from typing import Optional

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
VERDICTS = ("BLOCK", "HIGH_RISK", "INCOMPLETE", "NO_FINDINGS", "ERROR")


@dataclass
class Finding:
    severity: str            # critical | high | medium | low | info
    stage: str               # S0..S7
    code: str                # stable machine id, e.g. YARA:FG_EICAR_Test_File
    zh: str                  # Chinese description
    en: str                  # English description
    path: Optional[str] = None      # path inside the sample (relative), if any
    evidence: Optional[str] = None  # short evidence snippet (never executed)
    kind: str = "observed"          # observed | predicted (S5)
    downgraded: bool = False        # context-weighted (docs/CI/tests); excluded from medium corroboration

    def to_dict(self):
        return asdict(self)


@dataclass
class Missing:
    stage: str
    code: str
    zh: str
    en: str
    path: Optional[str] = None

    def to_dict(self):
        return asdict(self)


class ScanContext:
    """Mutable state carried through S0..S7 for one scan."""

    def __init__(self, scan_id, lang="zh"):
        self.scan_id = scan_id
        self.lang = lang
        self.findings: list[Finding] = []
        self.missing: list[Missing] = []
        self.stages: dict[str, dict] = {}
        self.meta: dict = {}
        self.files: list[dict] = []        # extracted file inventory (relative paths, sha256, size, type)
        self.deps: dict = {}
        self.footprint: list[dict] = []
        self.diff: dict = {}
        self.tools: dict = {}
        self.limitations: list[tuple[str, str]] = []
        self.deadline = None

    def add(self, *a, **kw):
        f = Finding(*a, **kw)
        key = (f.code, f.path, f.evidence)
        for x in self.findings:
            if (x.code, x.path, x.evidence) == key:
                return x
            # same detector, same file, one evidence string contained in the other: same occurrence
            if x.code == f.code and x.path == f.path and x.evidence and f.evidence \
                    and (f.evidence in x.evidence or x.evidence in f.evidence):
                if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(x.severity, 0):
                    x.severity = f.severity
                return x
        self.findings.append(f)
        return f

    def miss(self, stage, code, zh, en, path=None):
        m = Missing(stage, code, zh, en, path)
        if not any((x.code, x.path) == (code, path) for x in self.missing):
            self.missing.append(m)

    def stage(self, sid, status, zh="", en="", **extra):
        # status: done | partial | skipped | not_applicable | failed
        self.stages[sid] = {"status": status, "zh": zh, "en": en, **extra}

    def limit(self, zh, en):
        self.limitations.append((zh, en))


class ScanTimeout(Exception):
    pass
