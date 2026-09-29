"""The floor GUARD — reads the declaration in `floor.py`, refuses below it.

 (method) as corrected (source).

⚠ **THE FINDING THIS EXISTS FOR, AND IT IS NOT THAT THINGS CRASH.** The floor
was declared and nothing enforced it, so a cold start was run on Python 3.9.6 —
below the floor — and read as MET, twice, by readers who had every reason to be
careful. The shipped checks printed `OK (skipped=11)`, which is a pass; 32 of
the 44 shipped modules could not be imported at all, and the eleven skips were
the only trace.

> ***AN ARTEFACT RUN UNDER THE WRONG INTERPRETER DOES NOT ALWAYS STOP.
> SOMETIMES IT ANSWERS, AND THE ANSWER LOOKS LIKE THE RIGHT ONE.***

## The declaration is in this package, not in the connector's manifest

's guard read `manifest.json`. The method was adopted and the
source was ruled wrong: **the independent verifier must not need the
connector's packaging file to start.** `floor.py` holds the declaration;
`make_manifest.py` derives the manifest's `compatibility.runtimes.python` from
it. One declaration, two readers, and they cannot disagree.

## Nothing here is newer than the floor

⚠ **This module's whole job is to run correctly on an interpreter OLDER than
the floor.** It imports `sys` and nothing else, and uses no syntax past 3.8.
`floor.py`, which it reads, imports nothing at all.

## Where the guard must sit

FIRST, and first means first — before any other import at the entry point. A
stdlib import can be newer than the floor too: `boundry_verify.bodies` defines
`IdentifierKind(enum.StrEnum)`, which is 3.11+, and `__init__.py` imports it,
so a guard placed after that import never runs.
"""
# ─── CHANGE LEDGER ─────────────────────────────────────────────────────────
#   22 Sep 2026 · Created, reading `manifest.json`.
#   22 Sep 2026 · Source moved to `floor.py`; the
#                 connector's manifest is no longer read, and the two declared
#                 candidate paths it needed are gone with it.

import sys

__all__ = ["REFUSAL_CODE", "declared_floor", "below_floor", "assert_floor"]

# ⚠ A RELATIVE IMPORT ON PURPOSE. It binds this guard to the declaration
# shipped BESIDE it, so a `boundry_verify` copied anywhere carries its own
# floor. An absolute import could resolve to a different installation's.
from .floor import MAJOR as _MAJOR, MINOR as _MINOR, REFUSAL_CODE
from .floor import refusal as _refusal

#: `(major, minor)`, read at call time (`K-3`: import is definitions only).
def declared_floor():
    return (_MAJOR, _MINOR)


def below_floor(version=None):
    """`None` if the interpreter meets the floor, else the refusal sentence."""
    have = tuple(version or sys.version_info[:2])
    if have >= declared_floor():
        return None
    return _refusal(have[0], have[1], sys.executable)


def assert_floor():
    """FIRST act of every entry point. Exits 2 with the named refusal.

    ⚠ **`SystemExit`, NOT an exception to catch.** A caller that swallowed this
    would be back to answering under the wrong interpreter, which is the
    defect. Exit 2 distinguishes the refusal from a suite failure.

    ⚠ `tests.py` does NOT use this: under `unittest discover` the import-time
    `SystemExit` is CAUGHT and recorded as a failed test. It calls
    `below_floor()` and `os._exit(2)` itself, and says why.
    """
    problem = below_floor()
    if problem is not None:
        sys.stderr.write(problem + "\n")
        raise SystemExit(2)
