"""The declared minimum interpreter for this verifier. ONE declaration.

⚠ **THE FIRST CUT READ THE CONNECTOR'S `manifest.json`.** The method was right
and the source was not: `boundry_verify` is the INDEPENDENT verifier — the half
of this package a third party is meant to be able to take on its own — and a
verifier that cannot start without the connector's packaging file is not
independent. It was measured: `VERIFIER/` copied alone refused every selftest,
and the seat's own harness had to be given connector files to work around it.

> ***AN ARTEFACT THAT NEEDS ANOTHER ARTEFACT'S PAPERWORK TO START IS NOT THE
> INDEPENDENT ONE.***

So the floor is declared **here**, in the verifier, as two integers. Every
guard reads it from here, including the connector's; and `make_manifest.py`
DERIVES `manifest.json`'s `compatibility.runtimes.python` from it, so the
manifest's statement and the guard's cannot disagree.

## Why this file is so small, and must stay so

⚠ **It is imported by a guard whose whole job is to run on an interpreter older
than the floor.** Anything newer than the floor — a module, a syntax — would
crash before the refusal, which is the noisy failure wearing a check's name.
**This file imports NOTHING and uses no syntax past Python 2-era literals.**
It is a pair of integers and a string. Measured: it parses and executes on
3.9.6, and it has no imports to go wrong on anything older.

## Why not `sys.version_info` here

Reading the running interpreter is the GUARD's job, not the declaration's. A
declaration that looked at the interpreter would be a floor that moved with the
machine.
"""
# ─── CHANGE LEDGER ─────────────────────────────────────────────────────────
#   22 Sep 2026 ·. Created,
#                 moving the declaration out of the connector's `manifest.json`.

#: ⚠ **THE FLOOR, AND IT IS DECLARED NOWHERE ELSE.** Raising it is a decision
#: with a ledger entry, not an edit.
MAJOR = 3
MINOR = 12

#: The spec string the manifest carries, DERIVED from the pair above so the two
#: cannot drift. `make_manifest.py` imports this; it is never typed into JSON.
SPEC = ">=%d.%d" % (MAJOR, MINOR)

#: The named refusals. Codes, not sentences: a caller can match them and a
#: reader can grep every place the floor stopped something.
REFUSAL_CODE = "INTERPRETER-BELOW-DECLARED-FLOOR"
GUARD_UNAVAILABLE_CODE = "INTERPRETER-FLOOR-GUARD-UNAVAILABLE"

#: ⚠ **THE REFUSAL TEXT LIVES WITH THE DECLARATION, AND THAT IS NOT DECORATION.**
#: `tests.py` loads THIS FILE BY PATH — it must not execute
#: `boundry_verify/__init__.py`, whose imports can be newer than the floor. A
#: by-path load has no parent package, so anything it needs must be here and
#: must need no import. The first cut kept the text in the guard module and had
#: `tests.py` load THAT by path; the guard's `from .floor import …` then failed
#: with `attempted relative import with no known parent package`, and the
#: vocabulary sweep refused `home-raises-at-import`.
#:
#: > ***A MODULE LOADED BY PATH HAS NO PACKAGE, AND A RELATIVE IMPORT IS A
#: > PACKAGE'S PRIVILEGE.***
TEMPLATE = (
    "%s: this package declares Python >= %d.%d and is running under "
    "%d.%d (%s). REFUSING before doing any work.\n"
    "Nothing is wrong with your copy of the package. Run it on Python "
    "%d.%d or newer.\n"
    "This refusal exists because the alternative is worse: below the floor, "
    "32 of this package's 44 modules cannot be imported, and the self-tests "
    "still report OK with eleven checks quietly skipped."
)


def refusal(have_major, have_minor, executable):
    """The refusal sentence. No imports, so a by-path loader can call it."""
    return TEMPLATE % (REFUSAL_CODE, MAJOR, MINOR, have_major, have_minor,
                       executable, MAJOR, MINOR)
