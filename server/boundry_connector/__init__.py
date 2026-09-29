"""Boundry Verify — Stage 1, READ AND VERIFY.

Serves ONE
account: the operator's own, through Claude Desktop, over stdio.

⚠: this line opened "The PRIVATE Boundry connector". *Private* was a
programme word for a stage, and the package is now handed to reviewers who read it as a claim
about their data. The shape it describes has not changed — single-operator, non-production — and
`ladder.RUNTIME_WORDING` says exactly that on every answer.

⚠ **THIS PACKAGE IS ENGINE-ADJACENT, NOT ENGINE.** It lives outside
`ENGINE_ROOTS` (`compiler`, `substrate`, `manifest`), so the engine digest does
not move when it changes. *`compiler/api/` is 16 of the engine's 141 files;
building the connector there — which calls "the natural substrate" —
would have moved the neutrality digest and put a doorway inside the claim it
is supposed to be neutral about.*

⚠ **NOTHING HERE SIGNS.** 's rule for the independent verifier applies to
a connector for the same reason: a reader that can sign can manufacture the
evidence it reads. `test_connector_cx001.py` asserts the absence from outside
the module.

⚠ **NOTHING HERE ATTACHES TO A LIVE SUBSTRATE.** Every runtime SQLite attachment
in canon is `aiosqlite.connect(path)` / `sqlite3.connect(path)` — READ-WRITE; the
ONE exception is the offline rebuild command, which opens a COPY of a store
read-only — so *attaching in order to read is itself a
write* (journal files; `substrate/migrations.py` runs DDL). Measured, not
assumed: `test_G4_the_canon_census_of_every_substrate_attachment`.

⚠ The earlier wording said *every substrate connection*, and the census refused
it: `substrate/projection/backends_postgres.py` calls `psycopg.connect(dsn)` at
two sites. Those are substrate connections and they are not SQLite, so the
sentence was wider than the fact. They are named in the vector as the declared
exception — Stage 1 reaches neither, but **a sweep that lets "every" stand
because the point survives is not a sweep.** Stage 1 reads sealed
artefacts off disk and verifies them with the independent verifier, which is
pure.

⚠ **K-3.** Import is definitions only: no I/O, no clock, no network, nothing
executed. Every module here is importable clean.
"""

from __future__ import annotations

__all__ = ["STAGE", "TOOL_NAMES", "CONNECTOR_NAME", "CONNECTOR_DISPLAY_NAME", "CONNECTOR_VERSION"]

#: Stage 1 is READ AND VERIFY. Stage 2 (SUBMIT) is a separate ruled build.
STAGE = 1

#: ⚠⚠ **ONE IDENTITY, DECLARED ONCE.** The server
#: announced `boundry-private-connector` / `0.1.0-stage1` on `initialize` while
#: `manifest.json` said `boundry-connector` / `0.1.0` — two names and two versions
#: for one artefact, visible to any evaluator who compares the handshake with the
#: install. Both now come from HERE: `server.SERVER_INFO` reads these two names,
#: and `packaging/make_manifest.py` writes them into the manifest.
#:
#: **The identity that SHIPS is the handshake's**, because it is the governed one:
#: `boundry_connector.server.SERVER_INFO` is a register row, and `exp028` holds the
#: reason — *a connector that answered `initialize` with a stage it is not running
#: is a client reading the wrong contract off the handshake*. The version is
#: therefore BUILT from `STAGE`, so no edit can make the two disagree about it.
#: `0.1.0-stage1` is a valid semantic version with a pre-release tag.
#:
#: ⚠ **THE PUBLIC NAME**: the name, the display name and the
#: version are declared HERE and nowhere else. History: this package announced
#: `boundry-private-connector` / `0.1.0-stage1` until the rename landing.
#: The version is `0.3.0-stage1` ('s call, stated): the MINOR moves because
#: what a reader RECEIVES changed — `manifest.json` lost eleven annotation keys to pass the official
#: validator and gained `long_description` and `support`, the four release values are filled, and the
#: three shipped documents were rewritten for a reader outside the programme. No tool was added or
#: removed, so it is not a MAJOR; a reader comparing two copies must still see two versions.
#: The `-stage1` suffix is still BUILT from `STAGE`, because Stage 1 — read and verify, with no write
#: tool — is still what runs, and the README says so in as many words.
#: `0.3.1-stage1` (`ORDER_REV121`, `F-116`): the PATCH moves for one defect fixed — an unfilled
#: "Folders the connector may read" no longer replaces the packaged roots. No tool, tool schema or
#: refusal code changed; the manifest's roots field gained an empty default and GOV's wording
#: (`GEN2_RULINGS` G2.12).
CONNECTOR_NAME = "boundry-verify"
CONNECTOR_DISPLAY_NAME = "Boundry Verify"
CONNECTOR_VERSION = f"0.3.1-stage{STAGE}"

#: The registered tool surface, closed — **SEVEN tools**: the five of Stage 1, and the evaluation
#: kit's two ("at most two new tools, both read-only").
#:
#: ⚠ **THE WALL, NOT THE LOCK —, deciding 's filed
#: disagreement.** `submit_intent` was here, built as ordered and
#: recommended against: *a tool in a tool list is one a model reaches for, and a
#: refusal one flag from a write teaches the model the server is write-capable.*
#: **The name is gone from the listing and unknown to the dispatcher.**
#: Submission, when its day comes, arrives as a NEW tool under its own ruled
#: round — a wall now, a door later, never a lock a flag opens.
TOOL_NAMES: tuple[str, ...] = (
    "verify_record",
    "get_envelope",
    "query_envelopes",
    "chain_status",
    "explain_record",
    "check_plan_identity",
    "compare_runs",
)
