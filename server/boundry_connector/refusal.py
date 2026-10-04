"""One declared root for every refusal that crosses a boundary.

⚠ **WHY A ROOT, FROM THE FAILURE THAT ASKED FOR IT.** A measurement caught a raw
`sqlite3.OperationalError` escaping `export_for_client`: a snapshot with a hot
journal cannot be opened read-only, SQLite raised, and **the after-digest was
never taken — the one run that most needed "the store did not move" reported
nothing at all.** A caller cannot write `except OurRefusals` if our refusals are
eight unrelated classes and a third party's exceptions travel beside them.

> **EVERY REFUSAL RAISED IN `boundry_bridge` OR `boundry_connector` DESCENDS
> FROM `Refusal`, AND EVERY THIRD-PARTY EXCEPTION THAT REACHES A BOUNDARY IS
> WRAPPED IN ONE WITH THE ORIGINAL ATTACHED.**

⚠ **THE SCOPE IS THE ONE V3 ENFORCES, AND IT USED TO SAY "THIS PROGRAMME".**
`test_bridge_exp001.test_V3_every_refusal_in_both_packages_descends_from_one_root`
walks exactly two packages — the two named above — so a refusal raised anywhere
else in the programme was covered by the sentence and by nothing else.
A finding names three that live outside the root: `IgnoreRefused`, `WriteRefused`
and `FileRefused`. They are NOT re-parented here: that would make `REGISTERS/`
import the connector and invert the dependency.

> ***A SENTENCE THAT CLAIMS THE WHOLE PROGRAMME AND A VECTOR THAT WALKS TWO
> PACKAGES ARE NOT THE SAME PROMISE. THE PROSE MOVES TO THE VECTOR, BECAUSE THE
> VECTOR IS WHAT ANYONE CAN RUN.***

⚠ **THE ORIGINAL IS ATTACHED, NEVER DISCARDED.** `original` holds the exception
that caused it and `__cause__` is set, so a traceback still shows the SQLite
error and a caller that needs the vendor's error code can still reach it.
**Wrapping is a promise about the TYPE that crosses, not a decision to throw
information away** — the same shape: a boundary that swallows what it
catches is worse than one that never caught it.

⚠ **THIS DOES NOT MAKE A REFUSAL CORRECT.** It makes the set of types a caller
must handle closed and nameable. A second defect — a refusal that
misnamed its cause — is untouched by anything here.

⚠ **K-3.** Import is definitions only: no I/O, no clock, no network.
"""
from __future__ import annotations

__all__ = ["Refusal", "wrap", "shown"]

import re as _re

#: ⚠⚠ **A REFUSAL NEVER RENDERS A PATH — AND IT
#: CANNOT KNOW WHICH CLIENT-SUPPLIED STRING IS ONE.** Five refusals rendered a
#: value the client supplied — a record id, a tool name, an argument name, a
#: `tenant_scope`, a JSON-RPC method — and every one of them echoed a planted path
#: over a real pipe (attack `DEVB-10`, and a `record_id=
#: "../../../etc/passwd"`, whose echo was elided as "…"). So the rule is
#: stated about the VALUE, not the field: a value is rendered only if it is a
#: PLAIN IDENTIFIER — letters, digits, `.`, `_`, `-`, starting alphanumeric, no
#: `..`, at most 128 characters. A value carrying a path separator or a `..`
#: does not fit it, so what a refusal renders is at most one name — never a
#: route to one.
#:
#: > ***A RULE ABOUT WHICH FIELDS MAY CARRY A PATH IS A LIST, AND A LIST IS WHAT
#: > THE NEXT FIELD IS MISSING FROM. A RULE ABOUT WHAT A RENDERED VALUE MAY LOOK
#: > LIKE COVERS FIELDS NOBODY HAS WRITTEN YET.***
_PLAIN = _re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

WITHHELD = ("(a value that is not a plain identifier, withheld: a refusal never "
            "renders a path)")


def shown(value) -> str:
    """A client-supplied value as a refusal may render it: its `repr` if it is a
    plain identifier, and otherwise a statement that it was withheld."""
    if isinstance(value, str) and _PLAIN.fullmatch(value) and ".." not in value:
        return repr(value)
    return WITHHELD


class Refusal(Exception):
    """The one type a caller of the bridge or the connector must catch.

    ⚠ It lives in the CONNECTOR because the dependency runs one way: the bridge
    imports `boundry_connector.client_label` and nothing in the connector
    imports the bridge. **Measured, not assumed** — and the measurement is
    `test_connector_cx001.test_G4G6_no_connector_module_imports_the_bridge`,
    which derives every module under `boundry_connector/` by AST and carries a
    planted-import control. Until that vector existed the words said "measured"
    and named no measurement.

    > ***"MEASURED, NOT ASSUMED" IS ITSELF A CLAIM. IT IS THE ONE SENTENCE THAT
    > CANNOT BE LEFT STANDING ON ITS OWN AUTHORITY.***

    Putting the root in the lower layer is the only placement that does not
    invert that dependency.
    """

    #: The third-party exception this wraps, or `None` when the refusal is ours.
    original: BaseException | None = None


def wrap(exc: BaseException, cls: type, *args, **kwargs) -> Refusal:
    """Build a `cls` refusal carrying `exc`, with `__cause__` set.

    ⚠ **THE CALLER RAISES IT — this only builds it** — so that `raise ... from
    exc` reads at the boundary where the wrapping happens, and a reader sees the
    conversion rather than finding it in a helper.
    """
    if not issubclass(cls, Refusal):
        raise TypeError(f"{cls.__name__} does not descend from Refusal; a "
                        f"boundary may only raise refusals from the declared root")
    built = cls(*args, **kwargs)
    built.original = exc
    built.__cause__ = exc
    return built
