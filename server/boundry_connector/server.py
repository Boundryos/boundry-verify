"""The Stage-1 MCP server — JSON-RPC 2.0 over STDIO, stdlib at this module.

    python3 -m boundry_connector.server

⚠ **STDIO ONLY, ENFORCED IN CODE AND NOT ONLY IN PROSE.** The specification says a
remote connector is a Phase 7 event, and it states the directory-submission
gate in a sentence. **A sentence is one config line away from being ignored**
(/: a declaration enforces nothing; enforcement lives on the
path). So this module imports no networking library at all, and `main()`
REFUSES to start if it is handed any argument that looks like a transport,
host or port. `test_connector_cx001.py` asserts the absence of every socket
import from outside the module, because a control that cannot be checked from
outside is a claim.

⚠ **NO MCP PACKAGE, AND — SINCE THE TENANT-SCOPE RELOCATION — NO THIRD-PARTY
DEPENDENCY AT ALL.** MCP's local transport is line-delimited JSON-RPC 2.0 on
stdin/stdout, which the standard library covers, so no `mcp` package is
installed — that much was always true, and
`test_G4_no_mcp_package_is_imported_anywhere` checks it rather than leaving it
asserted.

⚠ **THIS BLOCK USED TO NAME A PYDANTIC CHAIN, AND THE CHAIN IS GONE.** It read
*"importing this module imports `pydantic`"* and walked the route hop by hop:
`scope.py` → `compiler.stages.query_execution` → `envelope_emitter` →
`compiler.types.envelope` → `pydantic`. **That was true when written and is not
true now.** The relocation moved the ONE tenant rule into
`compiler/stages/tenant_scope.py`, whose only runtime import is
`compiler.types.errors` (standard library only), and made
`compiler/types/__init__.py` inert so that importing a submodule of that package
no longer loads its models. The connector's seam is unchanged: it still imports
canon's one enforcement site and still re-types nothing.

The measurement is SHIPPED, not quoted, and two independent vectors make it —
`test_R2_the_pydantic_block_probe_RUNS_at_every_entry_point` starts a fresh
interpreter whose meta-path RAISES on any `pydantic` import and imports each
entry point in it, and `test_R2_the_connector_reaches_NO_third_party_module`
walks the closure by AST instead of running it:

    boundry_connector.server   imports clean with pydantic blocked
    boundry_connector.tools    imports clean with pydantic blocked
    boundry_connector.scope    imports clean with pydantic blocked

⚠ **AND BOTH INSTRUMENTS ARE SHOWN CAPABLE OF THE OTHER ANSWER.**
The probe is pointed at `compiler.types.envelope`, which does
import `pydantic`, and must report it reached; the closure walker is given a
planted seam module that imports `pydantic` and must find it. A detector that
has only ever returned "clean" has not detected anything.

> ***A CLAIM MADE TRUE BY NAMING THE PATH IS ONE A READER CAN RE-MEASURE. A
> CLAIM MADE TRUE BY SOFTENING THE WORDS IS ONE THEY MUST TAKE ON TRUST.***

⚠ put removing this dependency out of scope, and the sentence that
sat here said so. The relocation removed it as a CONSEQUENCE, not as its
purpose: the purpose was to let a verifier with no model layer READ the tenant
rule. The dependency going is the same fact seen from the other end.

⚠ **K-3.** Import is definitions only: nothing reads stdin, opens a file or
starts a loop until `main()` is called.
"""

from __future__ import annotations

# ⚠⚠ **THIS FILE IS RUN AS A SCRIPT, AND A PACKAGE MODULE RUN AS A SCRIPT HAS
# NO PACKAGE.** `manifest.json` launches it directly — the evaluator's only
# documented command. Measured: run that way, `__package__` is `None` and the
# package's own directory is `sys.path[0]`, so a relative import has no package
# context to resolve against and `boundry_connector` is not importable. Under
# `-I` the script's directory is not on `sys.path` at all.
#
# So the file puts its PARENT on the path and imports absolutely. The guard
# makes this a no-op for every ordinary import of the module.
#
# > ***A PACKAGE THAT ONLY IMPORTS WHEN SOMETHING ELSE SETS THE PATH HAS MADE
# > ITS LAUNCH COMMAND A THING THE READER HAS TO ALREADY KNOW.***
#
# ⚠ `os.path` only, never `Path.resolve()`: `resolve()` stats the filesystem and
# `K-3` is that import is definitions only — no I/O. `abspath` does not stat.
if __package__ in (None, ""):                       # script, not module
    import os as _os
    import sys as _sys

    _sys.path.insert(
        0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

# ⚠⚠ **THE DECLARED INTERPRETER FLOOR, SECOND ACT AND FIRST IMPORT.**
# It cannot be the very first statement: under
# `-I` this file has no route to its own package until the bootstrap above
# has run. It is the first thing after that, and before any module that could
# itself be newer than the floor.
#
# `manifest.json` has declared `>=3.12` since this package was first
# generated. Nothing enforced it, so a cold start was run on 3.9.6 and read as
# met — twice. Below the floor 32 of 44 shipped modules cannot be imported and
# the self-tests still say `OK`.
#
# > ***A DECLARATION NOTHING ENFORCES IS A PREFERENCE.***
from boundry_verify.interpreter_floor import assert_floor as _assert_floor

_assert_floor()

# ⚠: the floor as two integers, for the sentence below. It is the SAME
# declaration the guard above enforces and the manifest states, so the requirement a
# reader acts on cannot drift from the one that refuses them.
from boundry_verify.floor import MAJOR as _PY_MAJOR, MINOR as _PY_MINOR

from boundry_connector.refusal import Refusal

import json
import sys
from typing import Any

from boundry_connector import TOOL_NAMES
# ⚠: the instructions carry the corpus_dir sentence, DERIVED from the one place the two
# packaged labels are declared. A model reads this before it reads any schema.
from boundry_connector.corpus import CORPUS_DIR_WORDING as _CORPUS_DIR_WORDING
from boundry_connector import CONNECTOR_DISPLAY_NAME, CONNECTOR_NAME, CONNECTOR_VERSION
from boundry_connector import tools as _tools

__all__ = ["PROTOCOL_VERSION", "SERVER_INFO", "handle", "main",
           "TransportRefused"]

PROTOCOL_VERSION = "2024-11-05"

#: ⚠: DERIVED from `boundry_connector.CONNECTOR_NAME` / `CONNECTOR_VERSION`,
#: the one declaration `manifest.json` is also written from.
SERVER_INFO = {
    "name": CONNECTOR_NAME,
    "title": CONNECTOR_DISPLAY_NAME,
    "version": CONNECTOR_VERSION,
}

#: Shown to the model on `initialize`. It is external wording and it is flat.
INSTRUCTIONS = (
    "Boundry Verify, Stage 1: READ AND VERIFY only. Requires Python %d.%d or newer, "
    "and refuses to start below it. This server reads sealed " % (_PY_MAJOR, _PY_MINOR) +
    "artefacts from a directory on this machine and checks them with Boundry's "
    "independent verifier. It attaches to no live substrate, contacts nothing, "
    "and writes nothing. Every envelope tool requires an explicit tenant_scope "
    "and refuses without one. Verdicts are ATTESTED / REFUTED / ALTERED / "
    "UNATTESTED, and UNATTESTED always states a gap in the reader rather than a "
    "finding against a record. This server has NO write capability of any kind: "
    "there is no tool here that submits, seals, edits or deletes anything, and "
    "no setting that adds one. Every tool takes corpus_dir: " + _CORPUS_DIR_WORDING
)

#: Anything on the command line that would mean "listen somewhere".
_TRANSPORT_WORDS = ("--host", "--port", "--bind", "--http", "--sse",
                    "--listen", "--remote", "--tcp", "--socket", "--ws")


class TransportRefused(Refusal):
    """Raised when this server is asked to be anything but a local stdio pipe."""


def _result(request_id: Any, payload: dict) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def _error(request_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id,
            "error": {"code": code, "message": message}}


def handle(message: dict) -> dict | None:
    """One JSON-RPC message in, one response out (or None for a notification).

    ⚠ **IT CHANGES NO GLOBAL STATE, AND IT IS NOT PURE.** It READS seven
    module-level names — `INSTRUCTIONS`, `PROTOCOL_VERSION`, `SERVER_INFO`,
    `_error`, `_result`, `_tools` and `json` — measured by AST — and by `test_G4_handle_READS_exactly_the_seven_it_names`
and `test_G4_handle_CHANGES_no_module_level_state`, which carry the seven
as data so the function and this sentence must move together — and it writes
    none of them: no assignment to a module-level name, no `global` statement.

    > ***"PURE" AND "CHANGES NOTHING" ARE NOT THE SAME CLAIM, AND THE SMALLER ONE
    > IS THE TRUE ONE. A READER WHO TRUSTS THE LARGER WILL SWAP A MODULE-LEVEL
    > NAME AND EXPECT NOTHING TO MOVE.***

    What the vectors rely on is the true claim: because it changes nothing, they
    can drive it directly without a subprocess.
    """
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}

    if method == "initialize":
        return _result(request_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
            "instructions": INSTRUCTIONS,
        })
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "ping":
        return _result(request_id, {})
    if method == "tools/list":
        return _result(request_id, {"tools": list(_tools.TOOL_SCHEMAS)})
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        payload = _tools.dispatch(str(name), dict(arguments))
        # An MCP tool result is content; the refusal travels INSIDE it as data
        # rather than as a protocol error, so the model reads the reason code
        # and the ladder instead of a bare failure.
        return _result(request_id, {
            "content": [{"type": "text",
                         "text": json.dumps(payload, indent=2, sort_keys=True)}],
            "isError": payload.get("outcome") == "REFUSED",
        })
    if request_id is None:
        return None
    # ⚠: the method name is client-supplied and was echoed verbatim — a
    # planted path came back in the protocol error ( `DEVB-10`).
    return _error(request_id, -32601,
                  "method not found (the name is not echoed: this server never "
                  "renders client-supplied text in a refusal)")


def main(argv: list[str] | None = None) -> int:
    """Serve on stdin/stdout until EOF. Refuses any transport argument."""
    args = list(sys.argv[1:] if argv is None else argv)
    for arg in args:
        low = arg.lower()
        if any(low.startswith(w) for w in _TRANSPORT_WORDS):
            raise TransportRefused(
                f"refusing {arg!r}: this connector is STDIO-ONLY by "
                "construction. A remote endpoint is a Phase 7 event that would "
                "need auth review, key "
                "custody and operational grade — none of which this build has."
            )
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps(
                _error(None, -32700, "parse error")) + "\n")
            sys.stdout.flush()
            continue
        response = handle(message)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
