"""qapaths — shared path resolution for the _qa metric scripts.

Every path is derived from THIS FILE's location, so a script runs from any
working directory and in any git worktree. These scripts previously hardcoded
``C:\\Users\\User\\Downloads\\sd\\_qa``, which meant none of them ran anywhere
but the original author's machine.

Layout::

    <root>/_qa/fixtures/corpus   corpus sources + built DLLs  (committed)
    <root>/_qa/out/              ALL generated output         (gitignored)

Override the output root with ``DS_QA_OUT``.
"""

import os

# qapaths.py lives at <root>/_qa/metrics/qapaths.py
METRICS = os.path.dirname(os.path.abspath(__file__))
QA = os.path.dirname(METRICS)
ROOT = os.path.dirname(QA)

FIXTURES = os.path.join(QA, "fixtures")
CORPUS = os.path.join(FIXTURES, "corpus")

# Generated output. Kept out of the source tree so a clean checkout has none of
# it and .gitignore needs exactly one rule.
OUT = os.environ.get("DS_QA_OUT") or os.path.join(QA, "out")
DECOMP = os.path.join(OUT, "decomp")
PAIRS = os.environ.get("DS_PAIRS_DIR") or os.path.join(OUT, "pairs")
WORK = os.path.join(OUT, "work")
VERIFY = os.path.join(OUT, "verify")


def ensure_out(*paths):
    """Create the given output dirs (defaults to OUT) and return the first."""
    targets = paths or (OUT,)
    for p in targets:
        os.makedirs(p, exist_ok=True)
    return targets[0]


def find_vcvars():
    """Locate vcvars64.bat, or return None. VCVARS overrides the search."""
    env = os.environ.get("VCVARS")
    if env and os.path.isfile(env):
        return env
    pf = [
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    ]
    for base in pf:
        vs = os.path.join(base, "Microsoft Visual Studio")
        if not os.path.isdir(vs):
            continue
        for ver in sorted(os.listdir(vs), reverse=True):
            for ed in ("Community", "Professional", "Enterprise", "BuildTools"):
                cand = os.path.join(vs, ver, ed, "VC", "Auxiliary", "Build", "vcvars64.bat")
                if os.path.isfile(cand):
                    return cand
    return None
