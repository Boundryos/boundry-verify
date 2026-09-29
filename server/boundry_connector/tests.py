"""Checks you can run yourself, against this package, with nothing installed.

⚠ Named `tests.py` because `unittest discover` matches `test*.py`. The file
name is part of the documented command working; rename it and the command in
`README.md` silently finds nothing and reports success.

    python3 -I -B -m unittest discover server

⚠ **THIS FILE EXISTS BECAUSE A CITATION IS ONLY A STRENGTHENING IF THE READER
CAN FOLLOW IT**. The packaging documents used to cite test names from
the programme's own conformance suite — names of files that do not ship. A
reader could read the claim and not the proof.

**Every check below runs from this package alone.** Standard library only: no
`pytest`, no network, no fixtures, no third-party runner. `unittest` is in the
standard library and is the whole of the harness.

⚠⚠ **WHAT NEEDS A THIRD-PARTY MODULE — NOTHING, SINCE THE TENANT-SCOPE
RELOCATION.** The **verifier** (`boundry_verify`) is pure standard library. The
**server** used to reach `pydantic` through the kernel, via one import in
`scope.py`; the rule that import reaches now lives in
`compiler/stages/tenant_scope.py`, whose only runtime import is
`compiler.types.errors`, and `compiler/types/__init__.py` is inert. Measured by
importing `boundry_connector.server` and reading `sys.modules` against the
interpreter's site-packages: **five distributions before, zero now.**

* every **structural** check reads this package's own source and runs on a stock
  interpreter;
* the **behavioural** checks — refusal codes, tool dispatch, JSON-RPC over a
  real pipe — must IMPORT the server, and are SKIPPED with a named reason when
  it cannot be imported.

⚠ **THE GUARD IS NOT KEYED ON `pydantic` AND NEVER WAS.** `NEEDS_SERVER` asks
whether the server imports, not why it might not — which is why it keeps
working now that the answer has changed for one reason and can still be `no`
for another. On a stock 3.12 or newer, all 28 run and nothing skips. Below the
declared floor the package refuses before any of this.

**A skip here is a statement about your interpreter, not a check that failed.**

⚠ Determinism: no clock is read, no randomness is drawn, and no check depends
on the order the others ran in. Each builds and discards its own temporary
directory.
"""

from __future__ import annotations

# ⚠⚠ **THE FLOOR, FIRST ACT — AND THIS IS THE THIRD ENTRY POINT.**
# The floor ruling names `server.py` and `boundry_verify/__main__.py`. This file
# is the one the README tells a reader to run, and it is the one that produced
# Measured: on 3.9.6 it printed `OK (skipped=11)` while 32 of the package's 44
# modules could not be imported at all. **The artefact that reported the wrong
# answer must be the artefact that refuses.**
#
# It is guarded BEFORE `unittest` is imported, because the refusal must not
# depend on anything that could itself be newer than the floor.
#
# ⚠⚠ **AND IT EXITS HARD, WHICH THE OTHER TWO ENTRY POINTS DO NOT.** The shared
# guard raises `SystemExit(2)`, which is right for a script. Here the caller is
# `unittest discover`, and unittest CATCHES the import-time `SystemExit` and
# records it as a failed test: the refusal printed correctly and was then
# followed by a traceback and `FAILED (errors=1)`, exit 1 — which reads as a
# broken package rather than a wrong interpreter. Measured, then fixed.
#
# > ***A REFUSAL A TEST RUNNER CAN CATCH BECOMES A TEST RESULT, AND IS
# > EXACTLY THE COST OF A FLOOR BREACH ARRIVING AS A TEST RESULT.***
#
# The floor module is loaded BY PATH so that importing it does not execute
# `boundry_verify/__init__.py`, whose own imports may be newer than the floor.
import importlib.util as _ilu
import os as _os
import sys as _sys

#: ⚠ **TWO DECLARED PLACES THE VERIFIER SITS, AND NO THIRD.** In the built
#: package it is `server/boundry_verify/`; in the repository this file is
#: generated from it is `VERIFIER/boundry_verify/`. The first cut of this guard
#: knew only the first, so importing this module from the repository raised —
#: and the vocabulary sweep, which imports it to read `NOT_THE_SERVER`,
#: refused with `home-raises-at-import`. **A guard that breaks the tree it is
#: developed in gets removed by the next person who needs the tree.**
#:
#: ⚠ These locate the GUARD MODULE. They do not locate a floor: the floor is
#: declared in `boundry_verify/floor.py`, beside the guard, and travels with
#: it.
_SERVER = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_sys.path.insert(0, _SERVER)
_FLOOR_AT = (
    _os.path.join(_SERVER, "boundry_verify", "floor.py"),
    _os.path.join(_os.path.dirname(_SERVER), "VERIFIER", "boundry_verify",
                  "floor.py"),
)
_floor = None
for _cand in _FLOOR_AT:
    if _os.path.isfile(_cand):
        _spec = _ilu.spec_from_file_location("_boundry_floor", _cand)
        _floor = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_floor)
        break
if _floor is None:
    # ⚠ NOT a pass. A guard that cannot run has not found the floor met.
    _sys.stderr.write(
        "INTERPRETER-FLOOR-GUARD-UNAVAILABLE: floor.py is at none "
        "of the declared places %r. REFUSING: a floor check that cannot run "
        "has not found the floor met.\n" % (_FLOOR_AT,))
    _sys.stderr.flush()
    _os._exit(2)
_have = _sys.version_info[:2]
_problem = (None if _have >= (_floor.MAJOR, _floor.MINOR)
            else _floor.refusal(_have[0], _have[1], _sys.executable))
if _problem is not None:
    _sys.stderr.write(_problem + "\n")
    _sys.stderr.flush()
    _os._exit(2)                    # not SystemExit: unittest would catch it

import ast
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

#: This package, as shipped. Everything is resolved from here, so the checks
#: do not care where the package was unpacked.
PKG = pathlib.Path(__file__).resolve().parent
#: `server/`, which the manifest names as the payload root.
SERVER = PKG.parent
#: ⚠ The packaged corpus is a SIBLING of this package under `server/`,
#: not a subdirectory of it — that is how the bundle is laid out. The
#: first draft of these checks looked inside the package and every
#: verdict came back `corpus-root-absent`, which was this file being
#: wrong about the layout it ships in.
DEMO = SERVER / "demo_corpus"
#: The evaluation kit's evidence, the second packaged root, beside the demo.
KIT = SERVER / "kit_evidence"
#: The package root, where the documents sit beside `server/`.
ROOT = SERVER.parent


#: ⚠ **A NAMED EXEMPTION, NEVER A SILENT SKIP.** These checks ask what the
#: SERVER does. This file is not the server — it ships beside it and is never
#: imported by it. Without the exemption the checks match their own source:
#: this file calls `mkdir` to build its temporary directories, and it contains
#: the literal `synthetic import` inside the very assertion that forbids it.
#:
#: > ***AN INSTRUMENT THAT READS ITS OWN SOURCE IS MEASURING THE READER.***
#:
#: The exemption is one file, named here, so a reader can see exactly what is
#: outside the scan and check that nothing else is.
NOT_THE_SERVER = ("tests.py",)


def _sources() -> dict[str, str]:
    """The package's RUNTIME modules — this file excluded, by name."""
    return {p.name: p.read_text(encoding="utf-8")
            for p in sorted(PKG.glob("*.py")) if p.name not in NOT_THE_SERVER}


#: ⚠ **EVERY PREDICATE BELOW TAKES ITS SOURCES AS AN ARGUMENT.** That is the
#: whole point: a check calls it twice — once on the real package, where the
#: answer must be "no offenders", and once on a synthetic module that breaks
#: the rule, where the answer must NOT be "no offenders".
#:
#: > ***A CHECK THAT ONLY EVER READS CLEAN SOURCE CANNOT TELL "MEASURED AND
#: > HELD" FROM "MEASURED NOTHING". THE CONTROL IS WHAT SEPARATES THEM.***


def _imported_modules(sources: dict[str, str] | None = None) -> dict[str, set[str]]:
    """Every module each file imports, from the AST. Defaults to this package."""
    out: dict[str, set[str]] = {}
    for name, src in (_sources() if sources is None else sources).items():
        mods: set[str] = set()
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Import):
                mods |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods.add(node.module.split(".")[0])
                mods.add(node.module)
        out[name] = mods
    return out


def _literal(module: str, name: str):
    """A module-level literal, read from SOURCE without importing it.

    ⚠ This is how the structural checks avoid needing `pydantic`: the tool
    table is a literal, so it can be read rather than executed.
    """
    for node in ast.parse(_sources()[module]).body:
        targets = (node.targets if isinstance(node, ast.Assign)
                   else [node.target] if isinstance(node, ast.AnnAssign) else [])
        for t in targets:
            if isinstance(t, ast.Name) and t.id == name:
                return ast.literal_eval(node.value)
    raise AssertionError(f"{name} is not a module-level literal in {module}")


def _connector_importable() -> tuple[bool, str]:
    sys.path.insert(0, str(SERVER))
    try:
        import boundry_connector.tools  # noqa: F401
        return True, ""
    except Exception as exc:                       # pragma: no cover - env dependent
        return False, f"{type(exc).__name__}: {exc}"


CONNECTOR_OK, CONNECTOR_WHY = _connector_importable()

#: ⚠ **THE SKIP STATES THE OUTCOME AND CARRIES THE REASON VERBATIM. IT NAMES NO
#: CAUSE.** An earlier wording said "the server needs `pydantic`" — true on
#: Python 3.13 without it, and WRONG on the macOS system Python 3.9.6, where the
#: import stops at `enum.StrEnum` long before `pydantic` is reached. A skip line
#: that guesses the cause tells the reader something false on the very machine
#: where they most need the truth.
#:
#: > ***A SKIP REPORTS WHAT DID NOT HAPPEN AND WHAT THE INTERPRETER SAID. THE
#: > CAUSE IS THE READER'S TO DRAW FROM THE REASON, NOT THE INSTRUMENT'S TO
#: > ASSERT.***
#:
#: The structural checks above need none of this: they read source, not modules.
NEEDS_SERVER = unittest.skipUnless(
    CONNECTOR_OK,
    "the running server could not be imported in this interpreter "
    "(the verifier needs nothing) — reason, verbatim: " + CONNECTOR_WHY)


# ─────────────────────────────────────────────────────────────────────────────
# STRUCTURAL — these run on a stock interpreter, nothing installed
# ─────────────────────────────────────────────────────────────────────────────
class TheSurface(unittest.TestCase):
    """What this connector exposes, read from its own source."""

    def test_the_tool_surface_is_exactly_seven_and_they_are_the_declared_seven(self):
        """Five of Stage 1 and the evaluation kit's two."""
        names = _literal("__init__.py", "TOOL_NAMES")
        schemas = _literal("tools.py", "TOOL_SCHEMAS")
        self.assertEqual(len(names), 7, names)
        self.assertEqual(tuple(t["name"] for t in schemas), tuple(names))

    def test_there_is_no_write_tool_and_no_disabled_one(self):
        """⚠ The sixth name is absent everywhere a model can look: not in the
        tuple, not in the schema list, not in the dispatcher."""
        names = _literal("__init__.py", "TOOL_NAMES")
        src = _sources()
        self.assertNotIn("submit_intent", names)
        for where in ("tools.py", "server.py", "__init__.py"):
            self.assertNotIn("submit_intent", src[where].replace(
                "submit_intent` was here", "<historical reference>"))

    def test_every_tool_declares_a_title_and_the_four_hints(self):
        for tool in _literal("tools.py", "TOOL_SCHEMAS"):
            ann = tool.get("annotations")
            self.assertIsInstance(ann, dict, tool["name"])
            self.assertTrue(ann.get("title"), tool["name"])
            self.assertIs(ann.get("readOnlyHint"), True, tool["name"])
            self.assertIs(ann.get("destructiveHint"), False, tool["name"])
            self.assertIs(ann.get("idempotentHint"), True, tool["name"])
            self.assertIs(ann.get("openWorldHint"), False, tool["name"])

    def test_no_tool_name_carries_a_write_shaped_verb(self):
        verbs = {"submit", "create", "write", "update", "delete", "remove",
                 "insert", "put", "post", "patch", "set", "sign", "seal",
                 "publish", "send", "append", "attach", "revoke", "land"}
        for name in _literal("__init__.py", "TOOL_NAMES"):
            for part in name.split("_"):
                self.assertNotIn(part, verbs, name)


class WhatItCannotDo(unittest.TestCase):
    """The absences, each read from this package's imports by AST.

    ⚠ **Each check here runs TWICE: once on the shipped package, and once on a
    synthetic module planted to break the same rule.** The second run is the
    control. Without it the check would report green on an empty scan, and the
    reader could not tell that from a scan that found nothing wrong.
    """

    NETWORK = {"socket", "ssl", "http", "urllib", "requests", "httpx", "aiohttp",
               "uvicorn", "fastapi", "starlette", "websockets", "smtplib",
               "ftplib", "telnetlib", "asyncio", "selectors"}
    DATABASE = {"sqlite3", "aiosqlite", "psycopg", "psycopg2", "asyncpg"}
    SIGNING = {"nacl", "ecdsa", "cryptography", "Crypto", "OpenSSL"}
    WRITE_ATTRS = {"write_text", "write_bytes", "mkdir", "makedirs", "unlink",
                   "rmdir", "touch", "chmod", "rmtree", "copytree", "copyfile",
                   "move", "remove"}
    SUBSCRIBE = {"subscribe", "add_listener", "register_listener"}

    #: The planted modules. Each is a legal Python source that BREAKS exactly
    #: one rule, named so a failure says which control did not fire.
    PLANTED = {
        "NETWORK": "import socket\n",
        "DATABASE": "import sqlite3\n",
        "SIGNING": "def sign(payload):\n    return payload\n",
        "WRITE": "import pathlib\npathlib.Path('x').write_text('y')\n",
        "SUBSCRIBE": "bus.subscribe('records')\n",
        "EMITTER": "import envelope_emitter\n",
        "MCP": "import mcp.server\n",
    }

    # ── the predicates, each answering with the offenders it FOUND ───────────

    def _forbidden_imports(self, sources, forbidden):
        found = []
        for name, mods in _imported_modules(sources).items():
            hit = mods & forbidden
            if hit:
                found.append(f"{name}: {sorted(hit)}")
        return found

    def _signing(self, sources):
        found = self._forbidden_imports(sources, self.SIGNING)
        for name, src in sources.items():
            for node in ast.walk(ast.parse(src)):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name == "sign" or node.name.startswith("sign_"):
                        found.append(f"{name}:{node.lineno} def {node.name}")
        return found

    def _writes_or_subscribes(self, sources):
        """⚠ The STDIO transport's own `sys.stdout.write` is a NAMED exemption,
        not a silent skip: putting the reply on the pipe is the server's job."""
        found = []
        for name, src in sources.items():
            for node in ast.walk(ast.parse(src)):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                attr = fn.attr if isinstance(fn, ast.Attribute) else None
                if attr in self.WRITE_ATTRS or attr in self.SUBSCRIBE:
                    found.append(f"{name}:{node.lineno} {attr}")
                elif attr in ("write", "writelines"):
                    recv = ast.unparse(fn.value)
                    if recv not in ("sys.stdout", "sys.stderr"):
                        found.append(f"{name}:{node.lineno} {recv}.{attr}")
                elif isinstance(fn, ast.Name) and fn.id == "open":
                    mode = ""
                    if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                        mode = node.args[1].value or ""
                    if set(mode) & set("wax+"):
                        found.append(f"{name}:{node.lineno} open(mode={mode!r})")
        return found

    def _emitter_or_mcp(self, sources):
        found = []
        for name, mods in _imported_modules(sources).items():
            bad = [m for m in mods
                   if "emitter" in m or m == "mcp" or m.startswith("mcp.")]
            if bad:
                found.append(f"{name}: {sorted(bad)}")
        return found

    def _control(self, predicate, planted_key):
        """Run `predicate` over the planted module. It MUST report it."""
        planted = {f"planted_{planted_key.lower()}.py": self.PLANTED[planted_key]}
        self.assertTrue(
            predicate(planted),
            f"CONTROL DID NOT FIRE: the check passed a module that plants "
            f"{planted_key}, so a real {planted_key} offence would also pass")

    # ── the checks ───────────────────────────────────────────────────────────

    def test_it_opens_no_socket_and_contacts_no_endpoint(self):
        self.assertEqual(
            self._forbidden_imports(_sources(), self.NETWORK), [])
        self._control(lambda s: self._forbidden_imports(s, self.NETWORK),
                      "NETWORK")

    def test_it_attaches_to_no_database(self):
        self.assertEqual(
            self._forbidden_imports(_sources(), self.DATABASE), [])
        self._control(lambda s: self._forbidden_imports(s, self.DATABASE),
                      "DATABASE")

    def test_it_cannot_sign(self):
        self.assertEqual(self._signing(_sources()), [])
        self._control(self._signing, "SIGNING")

    def test_it_neither_writes_nor_subscribes(self):
        self.assertEqual(self._writes_or_subscribes(_sources()), [])
        self._control(self._writes_or_subscribes, "WRITE")
        self._control(self._writes_or_subscribes, "SUBSCRIBE")

    def test_it_imports_no_emitter_and_no_mcp_package(self):
        self.assertEqual(self._emitter_or_mcp(_sources()), [])
        self._control(self._emitter_or_mcp, "EMITTER")
        self._control(self._emitter_or_mcp, "MCP")

    def test_the_exemption_is_ONE_NAMED_FILE_and_nothing_else(self):
        """⚠ The exemption above is the one way these checks could be hollowed
        out. This is the check that watches it."""
        self.assertEqual(NOT_THE_SERVER, ("tests.py",))
        scanned = set(_sources())
        on_disk = {p.name for p in PKG.glob("*.py")}
        self.assertEqual(on_disk - scanned, {"tests.py"})


class TheDependencyChain(unittest.TestCase):
    """⚠ This package is NOT a bundle that needs nothing, and says so."""

    #: Each hop, as `server.py`'s own prose states it. Files inside this
    #: package are checked here; kernel hops are checked where they ship.
    IN_PACKAGE = (("server.py", "boundry_connector.tools"),
                  ("tools.py", "scope"))

    def test_the_chain_this_package_states_is_the_chain_it_has(self):
        src = _sources()
        for fname, target in self.IN_PACKAGE:
            mods: set[str] = set()
            for node in ast.walk(ast.parse(src[fname])):
                if isinstance(node, ast.Import):
                    mods |= {a.name for a in node.names}
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        mods.add(node.module)
                        mods |= {f"{node.module}.{a.name}" for a in node.names}
                    else:
                        mods |= {a.name for a in node.names}
            self.assertTrue(
                any(m == target or m.startswith(target + ".") for m in mods),
                f"{fname} no longer imports {target}")

    def test_the_kernel_hop_leaves_this_package_through_scope_only(self):
        """One enforcement import, in one file — the seam is not spread."""
        reaching = []
        for name, mods in _imported_modules().items():
            if any(m.split(".")[0] in ("compiler", "substrate") for m in mods):
                reaching.append(name)
        self.assertEqual(reaching, ["scope.py"], reaching)


class TheDocuments(unittest.TestCase):
    """The shipped documents, checked against the shipped code."""

    DOCS = ("README.md", "PRIVACY.md", "CONTACT.md", "LICENSE.txt", "manifest.json")
    FORBIDDEN = ("tamper-proof", "immutable", "guaranteed",
                 "we cannot read your data")

    def test_every_document_is_present(self):
        for d in self.DOCS:
            self.assertTrue((ROOT / d).is_file(), d)

    def test_no_document_makes_a_claim_the_code_does_not_hold(self):
        """⚠ A document that LISTS these words in order to disclaim them is
        doing the right thing, and this tells the two apart: the denial lives
        in one delimited block and is removed before the check."""
        for d in self.DOCS:
            text = (ROOT / d).read_text(encoding="utf-8")
            if d == "LICENSE.txt":
                # ⚠ The licence is a supplied document, shipped byte for byte and pinned by
                # digest. Its words are not this package's to edit, so they are not read for
                # claims about the code — it makes none.
                continue
            if d == "manifest.json":
                # ⚠ The manifest carries NO denial block. It once did, in a key
                # the official schema does not define; the schema is
                # `additionalProperties: false`, so the denial moved to the two
                # documents below and the manifest is read whole.
                pass
            else:
                while "<!-- WORDS-NOT-USED:START -->" in text:
                    a = text.index("<!-- WORDS-NOT-USED:START -->")
                    b = (text.index("<!-- WORDS-NOT-USED:END -->")
                         + len("<!-- WORDS-NOT-USED:END -->"))
                    text = text[:a] + text[b:]
            low = text.lower()
            for claim in self.FORBIDDEN:
                self.assertNotIn(claim, low, f"{d} claims {claim!r}")

    def test_the_manifests_tool_list_matches_the_code(self):
        doc = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
        named = tuple(t["name"] for t in doc["tools"])
        self.assertEqual(named, tuple(_literal("__init__.py", "TOOL_NAMES")))
        self.assertEqual(set(doc["tools"][0]), {"name", "description"})

    def test_the_manifests_tool_descriptions_are_the_codes(self):
        """⚠ Derived, not duplicated: the manifest's descriptions come from
        `TOOL_SCHEMAS`, so there is one source and nothing to keep in step."""
        doc = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
        code = {t["name"]: t["description"]
                for t in _literal("tools.py", "TOOL_SCHEMAS")}
        for entry in doc["tools"]:
            self.assertEqual(entry["description"], code[entry["name"]],
                             entry["name"])

    def test_the_manifests_contact_fields_are_real_and_agree_with_the_documents(self):
        """The four release values, as BUILT. `CONTACT.md` points a reader at each of these
        fields by name, so a placeholder here would make that document point at nothing.

        ⚠ RENAMED from `the_manifests_release_fields_are_HELD_or_real`, which accepted the
        placeholder because the values were not yet decided. They are, so the check
        that accepted a placeholder would now be the one thing between a filled release and
        an empty one."""
        doc = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
        author = doc["author"]
        name = author.get("name")
        self.assertTrue(isinstance(name, str) and name.strip(), "author.name")
        email = author.get("email")
        self.assertTrue(isinstance(email, str) and email.count("@") == 1
                        and "." in email.split("@")[1] and not email.split("@")[0].strip() == "",
                        f"author.email is not an address: {email!r}")
        urls = [doc.get("homepage"), doc.get("documentation")] + list(doc.get("privacy_policies") or [])
        self.assertEqual(len(urls), 3, "homepage, documentation and one privacy policy")
        for url in urls:
            self.assertTrue(isinstance(url, str) and url.startswith("https://"), url)
        # ⚠ A placeholder is not an address, wherever it came from. This is the string the
        # generator wrote into all four fields until the values were decided, ASSEMBLED
        # rather than quoted — the release gate refuses the quoted literal in any shipped
        # file, and a check that carried it would be the one file that could not ship.
        placeholder = "HE" + "LD"
        for field, value in (("author.name", name), ("author.email", email),
                             ("homepage", urls[0]), ("documentation", urls[1]),
                             ("privacy_policies[0]", urls[2])):
            self.assertNotIn(placeholder, str(value), field)
        # `CONTACT.md` names these five fields; if it stops, its table points at nothing.
        contact = (ROOT / "CONTACT.md").read_text(encoding="utf-8")
        for field in ("author.name", "author.email", "documentation", "privacy_policies[0]"):
            self.assertIn(field, contact, f"CONTACT.md no longer names {field}")

    def test_the_icon_ships_and_is_a_512_square_PNG(self):
        """The listing shows this file. It is BYTES: there is nothing in it to read, so what is
        checked is that it is there, that it is a PNG, and that it is the size the directory
        asks for — read out of the PNG header, with nothing installed."""
        icon = ROOT / "icon.png"
        self.assertTrue(icon.is_file(), "icon.png")
        raw = icon.read_bytes()
        self.assertEqual(raw[:8], b"\x89PNG\r\n\x1a\n", "not a PNG")
        self.assertEqual(raw[12:16], b"IHDR", "no header chunk where one must be")
        width = int.from_bytes(raw[16:20], "big")
        height = int.from_bytes(raw[20:24], "big")
        self.assertEqual((width, height), (512, 512), f"{width}x{height}")
        doc = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["icon"], "icon.png", "the manifest names a different icon")

    def test_the_interpreter_requirement_is_stated_and_DERIVED(self):
        """The one sentence a reviewer has to act on, in the two places they meet it.

        `server.type` is `python`, so the reviewer's OWN interpreter runs this server, and a
        stock macOS `python3` is refused by design. The floor is declared as a pair of
        integers in `boundry_verify/floor.py`; the manifest and the README state THAT pair,
        so the sentence and the guard that enforces it cannot disagree."""
        floor = _floor  # the module this file already loaded by path, before any other work
        stated = "Python %d.%d or newer" % (floor.MAJOR, floor.MINOR)
        doc = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
        self.assertIn(stated, doc["description"], "manifest description")
        self.assertIn(stated, doc.get("long_description", ""), "manifest long_description")
        self.assertEqual(doc["compatibility"]["runtimes"]["python"], floor.SPEC)
        self.assertIn(stated, (ROOT / "README.md").read_text(encoding="utf-8"), "README.md")

    def test_the_launch_command_points_at_a_file_that_is_here(self):
        doc = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
        args = doc["server"]["mcp_config"]["args"]
        self.assertIn("-I", args)
        self.assertIn("-B", args, "without -B the package rewrites itself when run")
        script = [a for a in args if a.endswith(".py")]
        self.assertEqual(len(script), 1, args)
        self.assertTrue((ROOT / script[0].replace("${__dirname}/", "")).is_file())


# ─────────────────────────────────────────────────────────────────────────────
# · EACH *Held by* NAME RESOLVES — read from the documents, checked here
# ─────────────────────────────────────────────────────────────────────────────
#: ⚠. The README says each *Held by* line names a check in
#: this run. Until these checks, that sentence was held by whoever read it.
#: Each backticked name in a *Held by* paragraph, and each name after "held by
#: the check" in `manifest.json`, must now resolve as one of seven kinds:
#:
#:   check      `test_<name>` is a check in this file
#:   symbol     `<module>.<name>` is defined at the top of a module of this
#:              package, or `<module>.<Class>.<name>` in that class's body
#:              (`boundry_connector.<name>` reads `__init__.py`)
#:   module     a dotted module path that ships under `server/`
#:   tool       a name in `TOOL_NAMES`, a tool this server registers
#:   document   a file that ships beside `server/`, or in one of the two packaged roots
#:   command    the README's own run command, character for character
#:   elsewhere  a reference outside this package, listed by exact token in
#:              `EveryHeldByLine.ELSEWHERE` with what it is
#:
#: A misspelt check name falls through to `elsewhere`, and `elsewhere` is an
#: exact list, so the misspelling fails unless somebody lists it.


def _held_by_paragraphs(docs: dict[str, str]) -> list[tuple[str, str]]:
    """`(document, text)` for each *Held by* in `docs`, a `{name: text}` map."""
    out: list[tuple[str, str]] = []
    for name, text in docs.items():
        if name.endswith(".json"):
            stack = [json.loads(text)]
            while stack:
                v = stack.pop()
                if isinstance(v, dict):
                    stack.extend(v.values())
                elif isinstance(v, list):
                    stack.extend(v)
                elif isinstance(v, str):
                    out.extend((name, v[m.start():])
                               for m in re.finditer(r"[Hh]eld by", v))
        else:
            out.extend((name, m.group(0)) for m in re.finditer(
                r"^\*Held by:\*.*?(?=\n[ \t]*\n|\Z)", text, re.S | re.M))
    return out


def _held_by_names(doc: str, text: str) -> list[str]:
    """The names one *Held by* makes: backticked in Markdown; in the manifest,
    the list after "held by the check(s)", up to ", which" or the full stop."""
    if doc.endswith(".json"):
        m = re.match(r"[Hh]eld by the checks? (.+?)(?:, which|\.|$)", text)
        return re.split(r",\s*|\s+and\s+", m.group(1)) if m else []
    return re.findall(r"`([^`]+)`", text)


def _checks_here() -> set[str]:
    """Each check in this file, as the documents spell it: without `test_`."""
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    return {f.name[len("test_"):] for c in tree.body if isinstance(c, ast.ClassDef)
            for f in c.body
            if isinstance(f, ast.FunctionDef) and f.name.startswith("test_")}


def _top_level_names(src: str, cls: str | None = None) -> set[str]:
    """Names bound at the top of `src`, or in the body of its class `cls`."""
    body = ast.parse(src).body
    if cls is not None:
        body = next((n.body for n in body
                     if isinstance(n, ast.ClassDef) and n.name == cls), [])
    names: set[str] = set()
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def _held_by_kind(token, elsewhere, checks, sources, command) -> str | None:
    """Which of the seven kinds `token` is, or `None` when it is none of them."""
    if token in checks:
        return "check"
    parts = token.split(".")
    if len(parts) in (2, 3):
        module = "__init__.py" if parts[0] == "boundry_connector" else parts[0] + ".py"
        cls = parts[1] if len(parts) == 3 else None
        if module in sources and parts[-1] in _top_level_names(sources[module], cls):
            return "symbol"
    if (len(parts) > 1 and all(p.isidentifier() for p in parts)
            and SERVER.joinpath(*parts[:-1], parts[-1] + ".py").is_file()):
        return "module"
    if token in _literal("__init__.py", "TOOL_NAMES"):
        return "tool"
    if "/" not in token and any((d / token).is_file() for d in (ROOT, DEMO, KIT)):
        return "document"
    if command is not None and token == command:
        return "command"
    if token in elsewhere:
        return "elsewhere"
    return None


def _unresolved_held_by(docs: dict[str, str], elsewhere) -> list[tuple[str, str]]:
    """`(document, what failed)` for each name that resolves as none of the seven
    kinds, each *Held by* from which no name can be read, and each README
    *Held by* that names a symbol or a document but not a check in this run."""
    checks, sources = _checks_here(), _sources()
    readme = ROOT / "README.md"
    found = (re.search(r"^    (python3 .+)$", readme.read_text(encoding="utf-8"), re.M)
             if readme.is_file() else None)
    command = found.group(1).strip() if found else None
    bad: list[tuple[str, str]] = []
    for doc, text in _held_by_paragraphs(docs):
        kinds = [(n, _held_by_kind(n, elsewhere, checks, sources, command))
                 for n in _held_by_names(doc, text)]
        bad.extend((doc, n) for n, k in kinds if k is None)
        if not kinds:
            bad.append((doc, "names nothing: " + text[:60]))
        if doc == "README.md" and not any(k == "check" for _, k in kinds):
            bad.append((doc, "names no check in this run: " + text[:60]))
    return bad


class EveryHeldByLine(unittest.TestCase):
    """The shipped documents' *Held by* lines, resolved against this package."""

    #: The references a *Held by* makes to things outside this package, each
    #: with what it is. A reader can follow these. This run matches each by its
    #: exact spelling and states what it is.
    ELSEWHERE = {
        "SPEC_Private_Connector_v1": "the connector specification; not shipped",
        "HANDOFF_operator_instructions.md": "the operator's instructions; not shipped",
        "substrate/model_provider.py": "a kernel file; not shipped",
        "PERMITTED_CALL_MODES": "a tuple in that kernel file",
        "CX-002": "a clause of the connector specification",
        "CX-003": "a clause of the connector specification",
        "EXP-006": "a programme experiment identifier",
        "FEED-004": "a clause identifier in the programme's specifications",
        "TEN-002": "a clause of the tenant-boundary specification",
        "D-119": "a programme decision identifier",
    }

    def _docs(self) -> dict[str, str]:
        return {d: (ROOT / d).read_text(encoding="utf-8")
                for d in TheDocuments.DOCS}

    def test_each_held_by_name_in_the_documents_RESOLVES(self):
        bad = _unresolved_held_by(self._docs(), self.ELSEWHERE)
        self.assertEqual(bad, [], "Held-by names that resolve to nothing")

    def test_the_held_by_lines_were_FOUND_in_each_document(self):
        """A reader that finds zero paragraphs resolves zero names. Counted
        per document: README 12, PRIVACY 4, CONTACT 1, the
        manifest 2; then README 20 with the kit's eight claims, 21 with the undecodable
        export, 22 with the privacy policy. When the manifest was cut back to the
        schema its two went with the keys that carried them, and PRIVACY dropped the one
        whose holder was an internal document a reader outside cannot open: 22, 3, 1. Addendum A
        added the licence line: 23, 3, 1; Addendum C added the corpus_dir labels: 24, 3, 1;
        `ORDER_REV121` added "Try it in Claude Desktop" with its four checks: 25, 3, 1. `LICENSE.txt` is absent from this map because it
        carries no *Held by* — it is a supplied document, not a claim this package makes."""
        found: dict[str, int] = {}
        for doc, _ in _held_by_paragraphs(self._docs()):
            found[doc] = found.get(doc, 0) + 1
        # ⚠ `manifest.json` is ABSENT from this map, and that is the change: its two *Held by*
        # sentences lived in keys the official schema does not define. They are in the README
        # and `PRIVACY.md` now, where the same resolver reads them.
        self.assertEqual(found, {"README.md": 25, "PRIVACY.md": 3,
                                 "CONTACT.md": 1})

    def test_honest_control_a_PLANTED_dangling_name_IS_caught(self):
        """⚠ The control. A check that was never written, a manifest name that
        was never written, a paragraph naming nothing, and a README line naming
        a symbol but no check are each caught, while the real check beside
        them is not."""
        planted = {
            "PLANTED.md": ("*Held by:* `a_check_nobody_wrote` and `it_cannot_sign`.\n"
                           "\n*Held by:* the vibes.\n"),
            "README.md": "*Held by:* `corpus.allowed_roots` in this package.\n",
            "planted.json": json.dumps(
                {"x": "held by the check a_json_check_nobody_wrote, which reads"}),
        }
        bad = _unresolved_held_by(planted, self.ELSEWHERE)
        named = sorted(what.split(":")[0] for _, what in bad)
        self.assertEqual(named, ["a_check_nobody_wrote", "a_json_check_nobody_wrote",
                                 "names no check in this run", "names nothing"],
                         bad)

    def test_the_README_states_the_number_of_checks_this_run_HAS(self):
        """The README's figure, against the loader's own count of this file."""
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        m = re.search(r"\*\*(\d+) checks, in this package", text)
        self.assertIsNotNone(m, "the README states no count")
        here = unittest.defaultTestLoader.loadTestsFromModule(
            sys.modules[__name__]).countTestCases()
        self.assertEqual(int(m.group(1)), here)


# ─────────────────────────────────────────────────────────────────────────────
# BEHAVIOURAL — these IMPORT the server; the structural checks read it
# ─────────────────────────────────────────────────────────────────────────────
@NEEDS_SERVER
class WhatItRefuses(unittest.TestCase):
    """⚠ The four corpus-root states, and the two codes that tell them apart."""

    def _corpus(self):
        from boundry_connector.corpus import Corpus, CorpusRefused, ROOTS_ENV
        return Corpus, CorpusRefused, ROOTS_ENV

    def test_a_folder_you_have_not_declared_is_refused_for_THAT(self):
        Corpus, CorpusRefused, ROOTS_ENV = self._corpus()
        with tempfile.TemporaryDirectory() as td:
            outside = pathlib.Path(td) / "not-declared"
            outside.mkdir()
            before = os.environ.get(ROOTS_ENV)
            os.environ[ROOTS_ENV] = f"demo={DEMO}"
            try:
                with self.assertRaises(CorpusRefused) as caught:
                    Corpus(outside).records()
                self.assertEqual(caught.exception.code, "corpus-root-not-declared")
            finally:
                if before is None:
                    os.environ.pop(ROOTS_ENV, None)
                else:
                    os.environ[ROOTS_ENV] = before

    def test_a_declared_root_that_is_absent_is_refused_for_ABSENCE(self):
        Corpus, CorpusRefused, ROOTS_ENV = self._corpus()
        with tempfile.TemporaryDirectory() as td:
            gone = pathlib.Path(td) / "declared-but-gone"
            before = os.environ.get(ROOTS_ENV)
            os.environ[ROOTS_ENV] = f"gone={gone}"
            try:
                with self.assertRaises(CorpusRefused) as caught:
                    Corpus(gone).records()
                self.assertEqual(caught.exception.code, "corpus-root-absent")
            finally:
                if before is None:
                    os.environ.pop(ROOTS_ENV, None)
                else:
                    os.environ[ROOTS_ENV] = before

    def test_the_two_refusals_are_told_APART(self):
        """⚠ The control: if both states gave one code, the operator who
        mistyped a path would be told the wrong thing about their own setup."""
        Corpus, CorpusRefused, ROOTS_ENV = self._corpus()
        codes = set()
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            present = td / "undeclared-present"
            present.mkdir()
            gone = td / "declared-gone"
            before = os.environ.get(ROOTS_ENV)
            os.environ[ROOTS_ENV] = f"gone={gone}"
            try:
                for target in (present, gone):
                    try:
                        Corpus(target).records()
                    except CorpusRefused as exc:
                        codes.add(exc.code)
            finally:
                if before is None:
                    os.environ.pop(ROOTS_ENV, None)
                else:
                    os.environ[ROOTS_ENV] = before
        self.assertEqual(codes, {"corpus-root-not-declared", "corpus-root-absent"})

    def test_UNSET_roots_mean_the_two_packaged_roots_and_nothing_else(self):
        """the README's line on the default roots was held by
        a reader reading `corpus.allowed_roots`. This is that reading, run. Two
        packaged roots since: the demo and the kit's evidence."""
        from boundry_connector import corpus
        before = os.environ.pop(corpus.ROOTS_ENV, None)
        try:
            self.assertEqual([p.resolve() for p in corpus.allowed_roots()],
                             [DEMO.resolve(), KIT.resolve()])
        finally:
            if before is not None:
                os.environ[corpus.ROOTS_ENV] = before

    # ⚠ `F-116` (`ORDER_REV121`): the check above tested an UNSET variable only; installed in Claude
    # Desktop with the field left empty (28 Sep 2026), 0.3.0 refused `kit` and `demo`. With "Folders
    # the connector may read" left empty the manifest's `${user_config.roots}` can arrive
    # unresolved, and 0.3.0 read it as a path that replaced the packaged roots — so `kit` and `demo`
    # both refused. The four checks below hold what the host actually hands over.

    def _roots_under(self, value):
        from boundry_connector import corpus
        before = os.environ.get(corpus.ROOTS_ENV)
        os.environ[corpus.ROOTS_ENV] = value
        try:
            return corpus.declared_roots(), corpus.resolve_root(corpus.KIT_LABEL)
        finally:
            if before is None:
                os.environ.pop(corpus.ROOTS_ENV, None)
            else:
                os.environ[corpus.ROOTS_ENV] = before

    def test_an_UNFILLED_host_placeholder_means_the_packaged_roots(self):
        """The manifest's own placeholder, unresolved, is the packaged pair, and `kit` resolves."""
        from boundry_connector import corpus
        roots, kit = self._roots_under("${user_config.roots}")
        self.assertEqual(roots, [(corpus.DEMO_LABEL, DEMO.resolve()),
                                 (corpus.KIT_LABEL, KIT.resolve())])
        self.assertEqual(kit, KIT.resolve())

    def test_whitespace_only_roots_mean_the_packaged_roots(self):
        for value in (" ", "\t", "  \n ", os.pathsep.join([" ", "\t", ""])):
            roots, _ = self._roots_under(value)
            self.assertEqual([p for _, p in roots], [DEMO.resolve(), KIT.resolve()], repr(value))

    def test_a_placeholder_beside_a_real_root_is_ignored_and_the_real_root_REPLACES_the_packaged_ones(self):
        with tempfile.TemporaryDirectory() as td:
            real = pathlib.Path(td).resolve()
            roots, kit = self._roots_under(os.pathsep.join(["${user_config.roots}", f"mine={real}"]))
            self.assertEqual(roots, [("mine", real)])
            # `kit` is no longer a declared label, so it is read as the path it spells.
            self.assertEqual(kit, pathlib.Path("kit"))

    def test_the_manifest_roots_field_defaults_to_EMPTY(self):
        """Belt and braces: the host is told to substitute the empty string, not a placeholder."""
        doc = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
        field = doc["user_config"]["roots"]
        self.assertIn("default", field)
        self.assertEqual(field["default"], "")

    # ⚠ `test_a_refusal_never_echoes_the_path_you_named` lived here and reached ONE
    # branch — the undeclared folder. A later pass found the absent-root
    # branch echoing, which this check could not see. It moved to
    # `NoRefusalEchoesAPath` below, keeping its NAME, and now drives EVERY refusal
    # code the package can raise — a set it derives from the source.


# ═══ · — WHAT A ROOT MAY HOLD, and the refusal by name ═══════════
#
# A measurement found a declared root holding a top-level JSON list answered by every tool with
# `tool-failed-unexpectedly`. A root now holds records, kernel exports and three files named
# one by one; a JSON file that is none of them refuses the root as `corpus-entry-not-a-record`,
# naming the root's LABEL and the file's SHAPE, and a path is not among the words.

_NOT_RECORDS = {"a top-level list": "[1, 2]", "a top-level scalar": "7",
                "an object with no record_id": '{"envelope_kind": "x"}'}


def _call_every_tool(root: pathlib.Path) -> dict:
    """Each of the seven tools, once, against `root`. Returns `{tool: answer}`."""
    from boundry_connector import tools
    g = {"corpus_dir": str(root), "tenant_scope": "global"}
    calls = {"verify_record": dict(g, record_id="r"), "get_envelope": dict(g, record_id="r"),
             "query_envelopes": g, "chain_status": g, "explain_record": dict(g, record_id="r"),
             "check_plan_identity": dict(g, run_id="r"),
             "compare_runs": dict(g, run_id_a="r", run_id_b="s")}
    return {name: tools.dispatch(name, args) for name, args in calls.items()}


@NEEDS_SERVER
class WhatARootMayHold(unittest.TestCase):
    """Every tool refuses a root holding a JSON file that is not a record, by name."""

    def test_a_NON_RECORD_json_file_is_REFUSED_by_name_by_every_tool(self):
        for shape, body in _NOT_RECORDS.items():
            with tempfile.TemporaryDirectory() as td:
                root = pathlib.Path(td) / _PLANTED
                root.mkdir()
                (root / "x.json").write_text(body)
                with _Declared(f"lab={root}"):
                    answers = _call_every_tool(root)
            for tool, got in answers.items():
                self.assertEqual(got.get("reason_code"), "corpus-entry-not-a-record", (shape, tool, got))
                self.assertIn(shape, got["detail"], (shape, tool))
                self.assertIn("'lab'", got["detail"], (shape, tool))
                self.assertEqual(_echoes(got["detail"], td, os.path.realpath(td)), [], (shape, tool))

    def test_honest_control_the_same_root_WITHOUT_the_file_is_READ(self):
        """The refusal is caused by the file: removed, the same root answers."""
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / "r"
            root.mkdir()
            (root / "rec.json").write_text(_a_record("rec-a-0001"))
            with _Declared(f"lab={root}"):
                self.assertEqual(_call_every_tool(root)["chain_status"]["outcome"], "OK")
                (root / "x.json").write_text("[1]")
                self.assertEqual(_call_every_tool(root)["chain_status"]["reason_code"],
                                 "corpus-entry-not-a-record")

    def test_a_NON_RECORD_file_is_refused_over_a_REAL_pipe(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / _PLANTED
            root.mkdir()
            (root / "x.json").write_text("[1, 2]")
            proc = subprocess.run(
                [sys.executable, "-I", "-B", str(SERVER / "boundry_connector" / "server.py")],
                input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                    "name": "compare_runs", "arguments": {
                        "corpus_dir": str(root), "run_id_a": "a", "run_id_b": "b",
                        "tenant_scope": "global"}}}) + "\n",
                capture_output=True, text=True, cwd=str(ROOT),
                env={"PATH": "/usr/bin:/bin", "BOUNDRY_CONNECTOR_ROOTS": f"lab={root}"})
        self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
        self.assertIn("corpus-entry-not-a-record", proc.stdout)
        self.assertEqual(_echoes(proc.stdout + proc.stderr, td, os.path.realpath(td)), [])


# ═══ · — an export whose contents do not decode ═══════════════════════
#
# A measurement found a kit export with correctly typed fields and a non-hex payload answering
# `tool-failed-unexpectedly` from the kit's three tools. It now refuses the root by name.

def _undecodable_variants() -> dict:
    base = json.loads((KIT / "calculation-m2.json").read_text(encoding="utf-8"))
    out = {}
    doc = json.loads(json.dumps(base)); doc["envelopes"][3]["payload_canonical_bytes"] = "zz-not-hex"
    out["a payload that is not hex"] = doc
    doc = json.loads(json.dumps(base)); doc["envelopes"][3]["payload_canonical_bytes"] = b"[1]".hex()
    out["a payload that is not a JSON object"] = doc
    doc = json.loads(json.dumps(base)); key = sorted(doc["bodies"])[0]; doc["bodies"][key] = "not hex"
    out["a body that is not hex"] = doc
    return out


@NEEDS_SERVER
class AnExportThatDoesNotDecode(unittest.TestCase):
    """Each of the seven tools refuses a root holding an undecodable export, by name."""

    def test_an_UNDECODABLE_export_is_REFUSED_by_name_by_every_tool(self):
        for what, doc in _undecodable_variants().items():
            with tempfile.TemporaryDirectory() as td:
                root = pathlib.Path(td) / _PLANTED
                root.mkdir()
                (root / "run.json").write_text(json.dumps(doc))
                with _Declared(f"lab={root}"):
                    answers = _call_every_tool(root)
            for tool, got in answers.items():
                self.assertEqual(got.get("reason_code"), "corpus-export-undecodable", (what, tool, got))
                self.assertIn("'lab'", got["detail"], (what, tool))
                self.assertEqual(_echoes(got["detail"], td, os.path.realpath(td)), [], (what, tool))

    def test_honest_control_the_same_root_with_the_INTACT_export_is_READ(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / "r"
            root.mkdir()
            (root / "run.json").write_text((KIT / "calculation-m2.json").read_text(encoding="utf-8"))
            with _Declared(f"lab={root}"):
                self.assertEqual(_call_every_tool(root)["chain_status"]["outcome"], "OK")

    def test_an_UNDECODABLE_export_is_refused_over_a_REAL_pipe(self):
        doc = _undecodable_variants()["a payload that is not hex"]
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / _PLANTED
            root.mkdir()
            (root / "run.json").write_text(json.dumps(doc))
            proc = subprocess.run(
                [sys.executable, "-I", "-B", str(SERVER / "boundry_connector" / "server.py")],
                input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                    "name": "check_plan_identity", "arguments": {
                        "corpus_dir": str(root), "run_id": "calculation-m2",
                        "tenant_scope": "global"}}}) + "\n",
                capture_output=True, text=True, cwd=str(ROOT),
                env={"PATH": "/usr/bin:/bin", "BOUNDRY_CONNECTOR_ROOTS": f"lab={root}"})
        self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
        self.assertIn("corpus-export-undecodable", proc.stdout)
        self.assertEqual(_echoes(proc.stdout + proc.stderr, td, os.path.realpath(td)), [])


# ═══ · THE EVALUATION KIT, checked in the package ════════════════════════
#
# The evidence in `kit_evidence/` came from real governed runs (`make_kit_evidence.py`, programme
# side). These checks read it through the tools and hold each claim the README makes about it.

def _kit(tool: str, **args) -> dict:
    from boundry_connector import tools
    return tools.dispatch(tool, dict(args, corpus_dir=str(KIT), tenant_scope="global"))


def _kit_exports() -> dict:
    out = {}
    for f in sorted(KIT.glob("*.json")):
        doc = json.loads(f.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and doc.get("export_format"):
            out[doc["run_id"]] = doc
    return out


@NEEDS_SERVER
class TheEvaluationKit(unittest.TestCase):
    """E1–E6 of design v0.2, each read back through the tools from the shipped evidence."""

    def test_E1_each_sealed_plan_recomputes_its_id_and_its_seal(self):
        runs = [r for r, d in _kit_exports().items() if not d.get("tampered_from")
                and d["workload"] != "refused"]
        self.assertGreaterEqual(len(runs), 2, runs)
        for run in runs:
            got = _kit("check_plan_identity", run_id=run)
            self.assertEqual(got.get("verdict"), "HOLDS", (run, got))

    def test_E1_the_answer_says_what_the_id_identifies(self):
        got = _kit("check_plan_identity", run_id="calculation-m2")
        self.assertIn("two different plan bodies can carry the same id", got["what_the_id_identifies"])

    def test_E2_the_same_request_on_each_platform_is_EQUIVALENT(self):
        by_workload: dict[str, list[str]] = {}
        for run, doc in _kit_exports().items():
            if not doc.get("tampered_from"):
                by_workload.setdefault(doc["workload"], []).append(run)
        self.assertEqual(sorted(by_workload), ["calculation", "refused", "transformation"])
        for workload, runs in by_workload.items():
            self.assertGreaterEqual(len(runs), 2, f"{workload}: one platform only: {runs}")
            got = _kit("compare_runs", run_id_a=runs[0], run_id_b=runs[1])
            self.assertEqual(got.get("verdict"), "EQUIVALENT", (workload, got))
            self.assertTrue(all(d["expected"] for d in got["differences"]), got["differences"])

    def test_E3_each_tampered_copy_is_caught_for_what_was_done_to_it(self):
        expected = {"output-byte-changed": ("DIVERGENT", "output-hash-mismatch"),
                    "forged-hash": ("DIVERGENT", "envelope-signature-fails"),
                    "output-lost": ("UNREACHABLE", "output-lost")}
        for how, (verdict, reason) in expected.items():
            got = _kit("compare_runs", run_id_a="calculation-m2", run_id_b=f"calculation-m2--{how}")
            self.assertEqual((got["verdict"], got["run_b"]["reason"]), (verdict, reason), how)

    def test_E4_the_refusal_is_a_signed_record_with_its_reason(self):
        got = _kit("explain_record", record_id="refused-m2")
        last = got["lineage"][-1]
        self.assertTrue(last["holds"], last)
        self.assertIn("COMP-ERR-305", last["detail"])
        # a run whose record ends in a refusal sealed a refusal, not a plan: the identity tool names that by code
        self.assertEqual(_kit("check_plan_identity", run_id="refused-m2")["reason_code"],
                         "run-sealed-no-plan")

    def test_E5_the_conduct_line_result_ships_with_its_instruments_digests(self):
        doc = json.loads((KIT / "CONDUCT_LINE_RESULT.json").read_text(encoding="utf-8"))
        self.assertEqual(doc["crossings_to_the_model_provider"], 0)
        self.assertEqual(doc["runtime_lock_permitted_call_modes"], ["stub"])
        self.assertEqual(len(doc["governed_phases"]), 8)
        for name, digest in doc["instrument_sha256"].items():
            self.assertRegex(digest, r"^[0-9a-f]{64}$", name)
        self.assertFalse(any(doc["model_provider_loaded_by_the_kit_runs"].values()))

    def test_E6_each_run_walks_link_by_link(self):
        for run, doc in _kit_exports().items():
            if doc.get("tampered_from"):
                continue
            got = _kit("explain_record", record_id=run)
            self.assertTrue(got.get("holds"), (run, [l for l in got["lineage"] if not l["holds"]]))

    def test_honest_control_a_CHANGED_intent_breaks_the_first_link(self):
        """E6's walk reads the submitted intent: one word changed, that link fails."""
        from boundry_connector import kit
        doc = _kit_exports()["calculation-m2"]
        key = json.loads((KIT / "key_directory.json").read_text(encoding="utf-8"))[doc["signing_key_id"]]
        doc["submitted_intent"]["intent_payload"]["operation_ref"] = "primitive:arithmetic.max_integers"
        links = kit.lineage(doc, key)
        self.assertFalse(links[1]["holds"], links[1])

    def test_the_kit_tools_answer_over_a_REAL_pipe(self):
        calls = [("check_plan_identity", {"run_id": "transformation-m2"}, '"verdict": "HOLDS"'),
                 ("compare_runs", {"run_id_a": "calculation-m2", "run_id_b": "calculation-m2--forged-hash"},
                  '"verdict": "DIVERGENT"'),
                 ("explain_record", {"record_id": "refused-m2"}, "COMP-ERR-305")]
        for tool, args, needle in calls:
            proc = subprocess.run(
                [sys.executable, "-I", "-B", str(SERVER / "boundry_connector" / "server.py")],
                input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                    "name": tool, "arguments": dict(args, corpus_dir=str(KIT),
                                                    tenant_scope="global")}}) + "\n",
                capture_output=True, text=True, cwd=str(ROOT), env={"PATH": "/usr/bin:/bin"})
            self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
            self.assertIn(needle, proc.stdout.replace('\\"', '"'), tool)


class ThePackagedRootsAreAddressableByNAME(unittest.TestCase):
    """the two packaged roots answer to `kit` and `demo`, over the wire, with nothing set.

    ⚠⚠ **THIS IS THE CHECK THAT WOULD HAVE CAUGHT IT.** Every shipped check before this one
    handed the tools a PATH it had computed itself, so every one of them passed while the package
    was unusable as installed: the only readable roots live inside the extension's install
    directory, nothing tells the model where that is, and a refusal may not say. A reviewer
    following the listing's own example prompts got `corpus-root-not-declared` every time.

    > ***A CHECK THAT SUPPLIES WHAT THE USER CANNOT HAS CHECKED THE CODE AND NOT THE PACKAGE.***

    So this one supplies what the listing supplies: the word `kit`, or the word `demo`, and
    nothing else — over a real pipe, with `BOUNDRY_CONNECTOR_ROOTS` unset.
    """

    def _speak(self, tool, arguments):
        proc = subprocess.run(
            [sys.executable, "-I", "-B", str(SERVER / "boundry_connector" / "server.py")],
            input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": tool, "arguments": arguments}}) + "\n",
            capture_output=True, text=True, cwd=str(ROOT), env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
        return proc.stdout.replace('\\"', '"')

    def test_the_two_packaged_roots_answer_to_their_LABELS_over_a_REAL_pipe(self):
        out = self._speak("compare_runs", {"corpus_dir": "kit", "run_id_a": "calculation-m2",
                                           "run_id_b": "calculation-linux-aarch64",
                                           "tenant_scope": "global"})
        self.assertIn('"verdict": "EQUIVALENT"', out, out[-400:])
        out = self._speak("query_envelopes", {"corpus_dir": "demo", "tenant_scope": "global"})
        self.assertIn('"outcome": "OK"', out, out[-400:])

    def test_a_label_that_is_not_declared_is_REFUSED_and_no_path_is_shown(self):
        """The unknown label, the label with a separator, and the label of a root nobody
        declared: each is a PATH the moment it is not a declared label, and each takes the
        refusal a path takes."""
        for value in ("kitt", "KIT", "kit/../..", "demo/..", "mine", str(ROOT)):
            out = self._speak("query_envelopes", {"corpus_dir": value, "tenant_scope": "global"})
            self.assertIn('"reason_code": "corpus-root-not-declared"', out, value)
            for fragment in (str(ROOT), str(SERVER), "/Users", "/private"):
                self.assertNotIn(fragment, out.replace(str(ROOT), "", 1) if value == str(ROOT) else out,
                                 f"{value}: a path was rendered")

    def test_the_wording_the_model_is_given_is_the_wording_that_RESOLVES(self):
        """One declaration: the schema, the instructions and the README say the same sentence,
        and the labels in it are the labels `declared_roots()` reports."""
        from boundry_connector import corpus as _corpus
        from boundry_connector import server as _server
        from boundry_connector import tools as _tools
        labels = [label for label, _ in _corpus.declared_roots()]
        self.assertEqual(sorted(labels), ["demo", "kit"])
        for label in labels:
            self.assertIn(f"`{label}`", _corpus.CORPUS_DIR_WORDING)
        for schema in _tools.TOOL_SCHEMAS:
            self.assertEqual(schema["inputSchema"]["properties"]["corpus_dir"]["description"],
                             "corpus_dir: " + _corpus.CORPUS_DIR_WORDING, schema["name"])
        self.assertIn(_corpus.CORPUS_DIR_WORDING, _server.INSTRUCTIONS)
        # ⚠ The README wraps its lines, so the comparison is over collapsed whitespace — and
        # over nothing else. A reworded sentence still fails; a rewrapped one does not.
        flat = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
        self.assertIn(" ".join(_corpus.CORPUS_DIR_WORDING.split()), flat)


class NoSigningKeyShips(unittest.TestCase):
    """Design v0.2: the kit ships verifying keys; a signing key and an HMAC secret are not in it."""

    def test_the_package_carries_verifying_keys_and_no_secret(self):
        for path in ROOT.rglob("*"):
            if not path.is_file():
                continue
            self.assertNotIn(path.suffix, (".pem", ".key", ".sqlite"), path.name)
            self.assertNotIn("hmac", path.name.lower(), path.name)
            # Assembled at run time: this file is in the walk, and a literal would find itself.
            self.assertNotIn(b"PRIVATE" + b" KEY-----", path.read_bytes(), path.name)
        for root in (DEMO, KIT):
            keys = json.loads((root / "key_directory.json").read_text(encoding="utf-8"))
            for key_id, value in keys.items():
                self.assertRegex(value, r"^[0-9a-f]{64}$", key_id)


# ═══ · THE BOUNDARY, ATTACKED —, ════════════════
#
# ⚠⚠ **WHY THESE EXIST**: *a check written by the author of
# the boundary tests the boundary the author imagined.* The checks above test the
# refusals the code was written to make. None planted a link, and the echo check
# reached one refusal branch, the undeclared folder. An attack broke both on a bare
# machine. These are the attacks, kept.

class _Declared:
    """Set `BOUNDRY_CONNECTOR_ROOTS` for one block and put it back."""

    def __init__(self, value):
        from boundry_connector.corpus import ROOTS_ENV
        self.env, self.value = ROOTS_ENV, value

    def __enter__(self):
        self.before = os.environ.get(self.env)
        os.environ[self.env] = self.value
        return self

    def __exit__(self, *exc):
        if self.before is None:
            os.environ.pop(self.env, None)
        else:
            os.environ[self.env] = self.before


def _link_or_skip(testcase, link, target, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:   # pragma: no cover - platform
        testcase.skipTest(f"this platform will not make a symlink here: "
                          f"{type(exc).__name__}")


def _file_openers(sources: dict[str, str] | None = None) -> set[tuple[str, str]]:
    """`(file, function)` for every call that OPENS a file — `open`, `os.open`,
    `io.open`, `Path.open`, `read_bytes`, `read_text` — in the RUNTIME modules."""
    found = set()
    for name, src in (_sources() if sources is None else sources).items():
        tree = ast.parse(src)
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for call in ast.walk(fn):
                if not isinstance(call, ast.Call):
                    continue
                f = call.func
                what = (f.id if isinstance(f, ast.Name)
                        else f.attr if isinstance(f, ast.Attribute) else "")
                if what in ("open", "read_bytes", "read_text"):
                    found.add((name, fn.name))
    return found


def _a_record(record_id):
    doc = json.loads((DEMO / "rec-a-0001.json").read_text(encoding="utf-8"))
    doc["record_id"] = record_id
    return json.dumps(doc)


class TheBoundaryUnderAttack(unittest.TestCase):
    """ (security): every file read resolves inside its declared root.

    **The rule, declared:** an entry is read only if its FINAL target lies inside
    the resolved declared root. A link that resolves INSIDE is admitted; one that
    resolves outside is refused `corpus-entry-outside-root`; a file with more than
    one name is refused `corpus-entry-hard-linked`, because a hard link has no
    target to check."""

    def _corpus(self):
        from boundry_connector.corpus import Corpus, CorpusRefused
        return Corpus, CorpusRefused

    def _layout(self, td):
        td = pathlib.Path(td)
        outside = td / "outside-a-clients-folder"
        outside.mkdir()
        (outside / "rec-b-0001.json").write_text(_a_record("rec-b-0001"))
        root = td / "declared"
        root.mkdir()
        return td, outside, root

    def test_a_FILE_link_to_outside_the_root_is_REFUSED_for_where_it_points(self):
        Corpus, CorpusRefused = self._corpus()
        with tempfile.TemporaryDirectory() as td:
            td, outside, root = self._layout(td)
            _link_or_skip(self, root / "rec-b-0001.json", outside / "rec-b-0001.json")
            with _Declared(f"c2={root}"):
                with self.assertRaises(CorpusRefused) as caught:
                    Corpus(root).records()
            self.assertEqual(caught.exception.code, "corpus-entry-outside-root")
            self.assertIn("'c2'", caught.exception.detail)
            self.assertNotIn(str(td), caught.exception.detail)

    def test_honest_control_the_SAME_record_COPIED_inside_the_root_is_read(self):
        """Without this the refusal above could be a connector that reads nothing."""
        Corpus, _ = self._corpus()
        with tempfile.TemporaryDirectory() as td:
            td, outside, root = self._layout(td)
            (root / "rec-b-0001.json").write_text(
                (outside / "rec-b-0001.json").read_text(encoding="utf-8"))
            with _Declared(f"c2={root}"):
                self.assertEqual([r.record_id for r in Corpus(root).records()],
                                 ["rec-b-0001"])

    def test_a_DIRECTORY_link_to_outside_is_REFUSED_both_as_an_entry_and_as_a_root(self):
        Corpus, CorpusRefused = self._corpus()
        with tempfile.TemporaryDirectory() as td:
            td, outside, root = self._layout(td)
            _link_or_skip(self, root / "x.json", outside, directory=True)
            _link_or_skip(self, root / "inner", outside, directory=True)
            with _Declared(f"c2={root}"):
                with self.assertRaises(CorpusRefused) as as_entry:
                    Corpus(root).records()
                with self.assertRaises(CorpusRefused) as as_root:
                    Corpus(root / "inner").records()
            self.assertEqual(as_entry.exception.code, "corpus-entry-outside-root")
            self.assertEqual(as_root.exception.code, "corpus-root-not-declared")

    def test_a_link_that_resolves_INSIDE_the_root_is_ADMITTED(self):
        """The declared answer 's open question, and its control: the
        rule is where a link LEADS, not that it is a link."""
        Corpus, _ = self._corpus()
        with tempfile.TemporaryDirectory() as td:
            td, outside, root = self._layout(td)
            (root / "real.json").write_text(_a_record("rec-inside"))
            _link_or_skip(self, root / "alias.json", root / "real.json")
            with _Declared(f"c2={root}"):
                ids = sorted(r.record_id for r in Corpus(root).records())
            self.assertEqual(ids, ["rec-inside", "rec-inside"])

    def test_a_RELATIVE_link_and_a_CHAIN_of_links_are_followed_to_the_END(self):
        Corpus, CorpusRefused = self._corpus()
        with tempfile.TemporaryDirectory() as td:
            td, outside, root = self._layout(td)
            chained = td / "declared-chain"
            chained.mkdir()
            _link_or_skip(self, root / "rel.json",
                          pathlib.Path("..") / outside.name / "rec-b-0001.json")
            _link_or_skip(self, chained / "hop", outside / "rec-b-0001.json")
            _link_or_skip(self, chained / "a.json", chained / "hop")
            with _Declared(f"c2={root}{os.pathsep}c4={chained}"):
                with self.assertRaises(CorpusRefused) as rel:
                    Corpus(root).records()
                with self.assertRaises(CorpusRefused) as chain:
                    Corpus(chained).records()
            self.assertEqual({rel.exception.code, chain.exception.code},
                             {"corpus-entry-outside-root"})

    def test_a_HARD_link_is_REFUSED_because_realpath_cannot_see_it(self):
        Corpus, CorpusRefused = self._corpus()
        with tempfile.TemporaryDirectory() as td:
            td, outside, root = self._layout(td)
            try:
                os.link(outside / "rec-b-0001.json", root / "rec-h.json")
            except OSError as exc:                  # pragma: no cover - platform
                self.skipTest(f"no hard link here: {type(exc).__name__}")
            with _Declared(f"c2={root}"):
                with self.assertRaises(CorpusRefused) as caught:
                    Corpus(root).records()
            self.assertEqual(caught.exception.code, "corpus-entry-hard-linked")

    def test_the_VERIFICATION_KEYS_and_the_EXPORT_MANIFEST_cannot_come_from_outside(self):
        """A key directory from outside would let a planted link choose the keys a
        signature is checked against; a manifest from outside would forge the one
        client comparison the connector makes. Neither may be passed over."""
        Corpus, CorpusRefused = self._corpus()
        with tempfile.TemporaryDirectory() as td:
            td, outside, root = self._layout(td)
            (outside / "keys.json").write_text("{}")
            (outside / "EXPORT_MANIFEST.json").write_text("{}")
            (root / "rec-a.json").write_text(_a_record("rec-a"))
            _link_or_skip(self, root / "key_directory.json", outside / "keys.json")
            _link_or_skip(self, root / "EXPORT_MANIFEST.json", outside / "EXPORT_MANIFEST.json")
            passed_over = td / "declared-notjson"
            passed_over.mkdir()
            (passed_over / "rec-a.json").write_text(_a_record("rec-a"))
            (passed_over / "EXPORT_MANIFEST.json").write_text("not json")
            with _Declared(f"c2={root}{os.pathsep}c5={passed_over}"):
                with self.assertRaises(CorpusRefused) as keys:
                    Corpus(root).key_directory()
                with self.assertRaises(CorpusRefused) as manifest:
                    Corpus(root).records()
                # the control: a manifest that is merely NOT JSON is passed over,
                # as before — only a manifest from OUTSIDE is an attack
                served = [r.record_id for r in Corpus(passed_over).records()]
            self.assertEqual({keys.exception.code, manifest.exception.code},
                             {"corpus-entry-outside-root"})
            self.assertEqual(served, ["rec-a"])

    def test_the_connector_OPENS_a_file_in_ONE_place(self):
        """Confinement holds only if every read goes through the confined one. A
        second `open()` anywhere in the package would read around it."""
        self.assertEqual(_file_openers(), {("corpus.py", "_confined_bytes")})

    def test_honest_control_a_SECOND_opener_IS_seen(self):
        planted = dict(_sources())
        planted["sneaky.py"] = "def g(p):\n    return open(p, 'rb').read()\n"
        self.assertIn(("sneaky.py", "g"), _file_openers(planted))

    @NEEDS_SERVER
    def test_GOVs_exact_attack_over_a_REAL_pipe_is_now_REFUSED(self):
        """Reproduced: a declared root holding
        `rec-b-0001.json → <outside>/rec-b-0001.json`, and `get_envelope` over the
        shipped launch command. It served the outside file. It must refuse; and
        the control, the same record copied inside, must be served — so the
        refusal is the link's and not the pipe's."""
        script = SERVER / "boundry_connector" / "server.py"
        with tempfile.TemporaryDirectory() as td:
            td, outside, root = self._layout(td)
            _link_or_skip(self, root / "rec-b-0001.json", outside / "rec-b-0001.json")
            copied = td / "declared-copy"
            copied.mkdir()
            (copied / "rec-b-0001.json").write_text(
                (outside / "rec-b-0001.json").read_text(encoding="utf-8"))
            answers = []
            for corpus_dir in (root, copied):
                call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "get_envelope", "arguments": {
                            "corpus_dir": str(corpus_dir), "record_id": "rec-b-0001",
                            "tenant_scope": "global"}}}
                proc = subprocess.run(
                    [sys.executable, "-I", "-B", str(script)],
                    input=json.dumps(call) + "\n", capture_output=True, text=True,
                    cwd=str(ROOT), env={"PATH": "/usr/bin:/bin",
                                        "BOUNDRY_CONNECTOR_ROOTS":
                                        f"c2={root}{os.pathsep}c3={copied}"})
                self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
                answers.append(json.loads(json.loads(proc.stdout)["result"]
                                          ["content"][0]["text"]))
        linked, control = answers
        self.assertEqual((linked["outcome"], linked["reason_code"]),
                         ("REFUSED", "corpus-entry-outside-root"))
        self.assertNotEqual(control["outcome"], "REFUSED", control)
        self.assertNotIn(str(td), json.dumps(linked))


#: ⚠⚠ ** — THE PATHS A REFUSAL MUST NEVER RENDER.** Each is planted where a
#: client, an operator or a record could put it, and each carries this token so
#: an echo cannot hide behind a resolved or shortened spelling.
_PLANTED = "a-clients-folder-name"


def _refusal_codes(sources: dict[str, str] | None = None) -> set[str]:
    """Every refusal code the package can raise TO A CLIENT, from the AST: the
    first argument of each `CorpusRefused(…)`, `ScopeRefused(…)` and `_refusal(…)`.
    Derived, never typed: a refusal site added tomorrow is in this set tomorrow."""
    codes = set()
    for src in (_sources() if sources is None else sources).values():
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                if (name in ("CorpusRefused", "ScopeRefused", "_refusal")
                        and node.args and isinstance(node.args[0], ast.Constant)
                        and isinstance(node.args[0].value, str)):
                    codes.add(node.args[0].value)
    return codes


def _echoes(text: str, *places) -> list[str]:
    """The planted things a rendered refusal gives back. Empty means it held."""
    found = [p for p in places if p and p in text]
    if _PLANTED in text:
        found.append(_PLANTED)
    return found


@NEEDS_SERVER
class NoRefusalEchoesAPath(unittest.TestCase):
    """ (privacy): EXP-006's rule at EVERY refusal site, not one."""

    def _drive(self, td):
        """Trigger every refusal code with a path planted where a caller could
        reach it. Returns `{code: rendered}`, and `{code: reason}` for any code
        this interpreter cannot drive — stated, never silently dropped."""
        from boundry_connector import tools
        from boundry_connector.corpus import Corpus, CorpusRefused
        from boundry_connector import server
        td = pathlib.Path(td)
        base = td / _PLANTED
        base.mkdir()
        got, cannot = {}, {}

        def keep(payload):
            if payload.get("outcome") == "REFUSED":
                got.setdefault(payload["reason_code"], json.dumps(payload))

        def corpus_refusal(fn):
            try:
                fn()
            except CorpusRefused as exc:
                got.setdefault(exc.code, f"{exc.code}: {exc.detail}")

        roots = {}
        def root(label, folder=None, **files):
            d = base / (folder or label)
            d.mkdir()
            for name, body in files.items():
                (d / name.replace("__", ".")).write_text(body)
            roots[label] = d
            return d

        good = root("good", rec__json=_a_record("rec-a-0001"))
        absent = base / "absent"
        badjson = root("badjson", x__json="not json")
        malformed = root("malformed", rec__json=_a_record("r"), EXPORT_MANIFEST__json=json.dumps(
            {"client_label": f"/Users/x/{_PLANTED}/Smith"}))
        # Two WELL-FORMED labels that disagree, minted from canon's RESERVED subspace
        # and validated here: a malformed pair is refused one branch earlier, and
        # canon may carry no issuable label (`EXP-015`), so none is typed.
        from boundry_connector.client_label import mint_synthetic, validate
        ours = mint_synthetic(issued=frozenset())
        theirs = mint_synthetic(issued=frozenset({ours}))
        validate(ours)
        validate(theirs)
        mismatch = root(ours, "mismatch", rec__json=_a_record("r"),
                        EXPORT_MANIFEST__json=json.dumps({"client_label": theirs}))
        notafile = root("notafile")
        (notafile / "y.json").mkdir()
        linked = root("linked")
        hard = root("hard")
        badpos = root("badpos", rec__json=json.dumps({"record_id": "r", "position": f"/{_PLANTED}/p"}))
        unreadable = root("unreadable", rec__json="{}")
        notarecord = root("notarecord", x__json="[1]")
        refused_run = (KIT / "refused-m2.json").read_text(encoding="utf-8")
        kitroot = root("kitroot", run__json=refused_run,
                       key_directory__json=(KIT / "key_directory.json").read_text(encoding="utf-8"))
        keyless = root("keyless", run__json=refused_run)
        broken = json.loads(refused_run)
        broken["envelopes"][0]["payload_canonical_bytes"] = f"/{_PLANTED}/not-hex"
        undecodable = root("undecodable", run__json=json.dumps(broken))
        (base / "outside.json").write_text(_a_record("o"))
        _link_or_skip(self, linked / "l.json", base / "outside.json")
        try:
            os.link(base / "outside.json", hard / "h.json")
        except OSError as exc:                      # pragma: no cover - platform
            cannot["corpus-entry-hard-linked"] = f"no hard link here: {type(exc).__name__}"
        declared = os.pathsep.join(f"{k}={v}" for k, v in roots.items()) + f"{os.pathsep}absent={absent}"

        with _Declared(declared):
            g = {"tenant_scope": "global"}
            keep(tools.dispatch("chain_status", {"corpus_dir": str(base / "undeclared"), **g}))
            keep(tools.dispatch("chain_status", {"corpus_dir": str(absent), **g}))
            for d in (badjson, malformed, mismatch, notafile, linked, hard, badpos, notarecord, undecodable):
                keep(tools.dispatch("chain_status", {"corpus_dir": str(d), **g}))
            keep(tools.dispatch("chain_status", {"corpus_dir": str(good)}))
            keep(tools.dispatch("chain_status", {"corpus_dir": str(good), "tenant_scope": f"/{_PLANTED}/s"}))
            keep(tools.dispatch("query_envelopes", {"corpus_dir": str(good), "tenant_scope": "per_tenant"}))
            keep(tools.dispatch("get_envelope", {"corpus_dir": str(good), "record_id": f"../{_PLANTED}/r", **g}))
            keep(tools.dispatch("chain_status", {"corpus_dir": str(good), f"/{_PLANTED}/k": 1, **g}))
            keep(tools.dispatch(f"/{_PLANTED}/tool", {}))
            keep(tools.dispatch("check_plan_identity", {"corpus_dir": str(kitroot), "run_id": "refused-m2", **g}))
            keep(tools.dispatch("check_plan_identity", {"corpus_dir": str(keyless), "run_id": "refused-m2", **g}))
            corpus_refusal(lambda: Corpus(good).record(f"../{_PLANTED}/r"))
            if hasattr(os, "geteuid") and os.geteuid() == 0:   # pragma: no cover - env
                cannot["corpus-entry-unreadable"] = ("running as root, whom mode 000 "
                                                     "does not stop from reading")
            else:
                os.chmod(unreadable / "rec.json", 0)
                keep(tools.dispatch("chain_status", {"corpus_dir": str(unreadable), **g}))
                os.chmod(unreadable / "rec.json", 0o600)
            method = server.handle({"jsonrpc": "2.0", "id": 7, "method": f"/{_PLANTED}/m"})
            got["(json-rpc method not found)"] = json.dumps(method)
        return got, cannot, str(td)

    def test_a_refusal_never_echoes_the_path_you_named(self):
        """`EXP-006`, WIDENED to every refusal site the package can raise. The
        old form of this check reached one branch; found another."""
        with tempfile.TemporaryDirectory() as td:
            got, cannot, place = self._drive(td)
        for code, rendered in sorted(got.items()):
            self.assertEqual(_echoes(rendered, place, os.path.realpath(place)), [],
                             f"{code} echoed a planted path: {rendered[:300]}")

    def test_every_refusal_code_the_package_can_raise_IS_driven_here(self):
        """The coverage is DERIVED from the source. A refusal site with no driver
        above fails HERE — which is how absent-root went unchecked for so long."""
        with tempfile.TemporaryDirectory() as td:
            got, cannot, _ = self._drive(td)
        derived = _refusal_codes()
        # ⚠ The vacuity guard: an AST scan that found NOTHING would make the
        # assertion below pass on an empty set. It must find the codes that exist.
        self.assertTrue({"corpus-root-absent", "corpus-entry-outside-root",
                         "tool-not-registered"} <= derived, sorted(derived))
        missing = derived - set(got) - set(cannot)
        self.assertEqual(missing, set(), f"refusal codes nothing here plants into: {sorted(missing)}")

    def test_honest_control_a_PLANTED_refusal_site_IS_derived(self):
        """The derivation, shown to see a site nobody has written yet."""
        planted = {"future.py": 'def f():\n    raise CorpusRefused("a-code-from-tomorrow", "x")\n'}
        self.assertIn("a-code-from-tomorrow", _refusal_codes(planted))

    def test_a_PLAIN_identifier_is_SHOWN_and_anything_else_is_WITHHELD(self):
        from boundry_connector.refusal import shown, WITHHELD
        self.assertEqual(shown("rec-a-0001"), "'rec-a-0001'")
        for bad in ("/etc/passwd", "a/b", "../x", "..", "x" * 129, "C:\\x", " a", "", 5, None):
            self.assertEqual(shown(bad), WITHHELD, repr(bad))

    def test_a_TypeError_INSIDE_a_tool_is_not_an_ARGUMENT_refusal(self):
        """The arguments are BOUND before the tool runs, so a fault inside a tool
        is reported as a fault — and its text, which may carry a path, is not."""
        from boundry_connector import tools

        def planted_tool(*, corpus_dir):
            raise TypeError(f"inside the tool, about {corpus_dir}")

        tools._DISPATCH["planted_tool"] = planted_tool
        try:
            bound = tools.dispatch("planted_tool", {"corpus_dir": f"/{_PLANTED}"})
            unbound = tools.dispatch("planted_tool", {"nope": 1})
        finally:
            del tools._DISPATCH["planted_tool"]
        self.assertEqual(bound["reason_code"], "tool-failed-unexpectedly")
        self.assertEqual(_echoes(json.dumps(bound)), [])
        self.assertEqual(unbound["reason_code"], "tool-arguments-rejected")

    def test_honest_control_an_ECHOING_refusal_IS_caught(self):
        """The scanner, shown able to see what it looks for — on the exact text
        the absent-root branch used to render."""
        with tempfile.TemporaryDirectory() as td:
            place = str(pathlib.Path(td) / _PLANTED)
            for spelling in (place, os.path.realpath(place)):
                planted = f"corpus-root-absent: no artefact directory at {spelling}; …"
                self.assertNotEqual(_echoes(planted, place), [], spelling)


def _handshake_identity() -> tuple[str, str, str]:
    """`serverInfo`, as a client reads it: over the shipped launch command."""
    script = SERVER / "boundry_connector" / "server.py"
    proc = subprocess.run(
        [sys.executable, "-I", "-B", str(script)],
        input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                          "params": {}}) + "\n",
        capture_output=True, text=True, cwd=str(ROOT), env={"PATH": "/usr/bin:/bin"})
    if proc.returncode != 0:
        raise AssertionError(proc.stderr[-400:])
    info = json.loads(proc.stdout)["result"]["serverInfo"]
    return info["name"], info.get("title"), info["version"]


def _disagreement(manifest: pathlib.Path) -> tuple | None:
    """`None` when the handshake and `manifest` name one artefact; otherwise both."""
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    shaken, declared = _handshake_identity(), (doc["name"], doc.get("display_name"), doc["version"])
    return None if shaken == declared else (shaken, declared)


@NEEDS_SERVER
class OneIdentity(unittest.TestCase):
    """The handshake and the manifest name ONE thing, from one declaration."""

    def test_serverInfo_over_a_REAL_pipe_IS_the_manifests_name_and_version(self):
        self.assertIsNone(_disagreement(ROOT / "manifest.json"))

    def test_honest_control_a_manifest_that_DISAGREES_is_seen_to(self):
        """The SAME comparison, over the SAME pipe, against a manifest carrying the
        identity this package shipped with before: it must disagree."""
        doc = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
        doc["name"], doc["display_name"], doc["version"] = "boundry-connector", None, "0.1.0"
        with tempfile.TemporaryDirectory() as td:
            planted = pathlib.Path(td) / "manifest.json"
            planted.write_text(json.dumps(doc), encoding="utf-8")
            self.assertIsNotNone(_disagreement(planted))


#: The identity this package carried before the release landing, ASSEMBLED at run time: this
#: file is in the scan below, and a literal would find itself.
_OLD_IDENTITY = "boundry-" + "private-connector"


def _old_identity_outside_history(docs: dict[str, str], sources: dict[str, str]) -> list[str]:
    """Where the old public identity appears outside a HISTORY block (documents) or in a string
    constant (source; a comment may record it). Empty means the rename is whole."""
    found = []
    for name, text in docs.items():
        while "<!-- HISTORY:START -->" in text:
            a = text.index("<!-- HISTORY:START -->")
            b = text.index("<!-- HISTORY:END -->") + len("<!-- HISTORY:END -->")
            text = text[:a] + text[b:]
        if _OLD_IDENTITY in text:
            found.append(name)
    for name, src in sources.items():
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and _OLD_IDENTITY in node.value:
                found.append(name)
    return sorted(set(found))


class TheReleaseIdentity(unittest.TestCase):
    """The public name is Boundry Verify, and the old one survives as history only."""

    def test_the_old_public_identity_appears_only_as_history(self):
        docs = {d: (ROOT / d).read_text(encoding="utf-8") for d in TheDocuments.DOCS}
        self.assertEqual(_old_identity_outside_history(docs, _sources()), [])

    def test_honest_control_a_document_carrying_the_old_identity_IS_caught(self):
        planted = {"PLANTED.md": f"This server is {_OLD_IDENTITY}.",
                   "HISTORY.md": f"<!-- HISTORY:START -->was {_OLD_IDENTITY}<!-- HISTORY:END -->"}
        source = {"planted.py": f"NAME = {_OLD_IDENTITY!r}\n# was {_OLD_IDENTITY}\n"}
        self.assertEqual(_old_identity_outside_history(planted, source), ["PLANTED.md", "planted.py"])


@NEEDS_SERVER
class WhatItAnswers(unittest.TestCase):
    """The packaged synthetic corpus, verified by the independent verifier."""

    def _tools(self):
        from boundry_connector import tools
        return tools

    def setUp(self):
        """⚠ The packaged corpus must be DECLARED, like any other root.

        The first draft of these checks did not declare it and every verdict
        came back `REFUSED` — which is the connector behaving correctly and the
        check being wrong. Unset means the packaged corpus and nothing else is
        readable; it still has to be named to be read.
        """
        from boundry_connector.corpus import ROOTS_ENV
        self._env_before = os.environ.get(ROOTS_ENV)
        self._roots_env = ROOTS_ENV
        os.environ[ROOTS_ENV] = f"demo={DEMO}"

    def tearDown(self):
        if self._env_before is None:
            os.environ.pop(self._roots_env, None)
        else:
            os.environ[self._roots_env] = self._env_before

    def test_the_packaged_corpus_verifies(self):
        out = self._tools().verify_record(
            corpus_dir=str(DEMO),
            record_id="rec-a-0001", tenant_scope="global")
        self.assertEqual(out["outcome"], "ATTESTED", out)

    def test_a_tampered_record_is_ALTERED_and_a_bad_signature_is_REFUTED(self):
        """⚠ The corpus demonstrates its FAILURE modes, not only its success —
        and the two failures are distinct answers, not one word."""
        seen = {}
        for rid in ("rec-b-0002-tampered", "rec-a-0003-badsig"):
            seen[rid] = self._tools().verify_record(
                corpus_dir=str(DEMO),
                record_id=rid, tenant_scope="global")["outcome"]
        self.assertEqual(seen["rec-b-0002-tampered"], "ALTERED", seen)
        self.assertEqual(seen["rec-a-0003-badsig"], "REFUTED", seen)

    def test_a_read_with_no_declared_scope_REFUSES_and_is_not_widened(self):
        out = self._tools().get_envelope(
            corpus_dir=str(DEMO),
            record_id="rec-a-0001", tenant_scope=None)
        self.assertEqual(out["outcome"], "REFUSED", out)

    def test_an_unknown_tool_name_REFUSES_and_never_guesses(self):
        out = self._tools().dispatch("chain_status_v2", {})
        self.assertEqual(out["outcome"], "REFUSED", out)


@NEEDS_SERVER
class OverTheWire(unittest.TestCase):
    """⚠ What a model actually reads is `tools/list`, not the source."""

    def _speak(self, message):
        script = SERVER / "boundry_connector" / "server.py"
        proc = subprocess.run(
            [sys.executable, "-I", "-B", str(script)],
            input=json.dumps(message) + "\n",
            capture_output=True, text=True, cwd=str(ROOT),
            env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
        return json.loads(proc.stdout)

    def test_the_shipped_launch_command_starts_the_server(self):
        got = self._speak({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        listed = got["result"]["tools"]
        self.assertEqual([t["name"] for t in listed],
                         list(_literal("__init__.py", "TOOL_NAMES")))

    def test_the_annotations_reach_the_client_over_a_real_pipe(self):
        got = self._speak({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        for tool in got["result"]["tools"]:
            self.assertIs(tool["annotations"]["readOnlyHint"], True, tool["name"])

    def test_the_sixth_name_is_absent_over_the_wire_too(self):
        got = self._speak({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertNotIn("submit", json.dumps(got).lower())


if __name__ == "__main__":                          # pragma: no cover
    unittest.main()
