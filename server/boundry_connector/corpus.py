"""The read-only artefact source — the MINIMAL non-production instance.

⚠ **The question was what the minimal non-production instance is. The
answer this build reached is: NOT AN INSTANCE.**

Every runtime SQLite attachment in canon is `aiosqlite.connect(path)` or
`sqlite3.connect(path)` — **read-write; the ONE exception is the offline
rebuild command, which opens a COPY of a store read-only** — and `substrate/migrations.py` runs DDL. Counted by
`test_G4_the_canon_census_of_every_substrate_attachment`, which also names the
two `psycopg.connect(dsn)` sites in `substrate/projection/backends_postgres.py`
as the declared non-SQLite exception. So *opening a substrate in order
to read it is a write*: journal and shared-memory files appear beside the
database, and a schema may move. A tool surface with no write verbs on top of a
read-write attachment is not a read-only connector; it is a read-only
VOCABULARY over a writing session.

So Stage 1 attaches to nothing. It reads **sealed artefacts as files** from a
directory the operator names, opens them `"rb"`, and hands them to the
independent verifier, which is pure. The directory is the instance, the
filesystem's own read permission is the enforcement, and the honest test of
"non-production" becomes trivial to state and to check: *the connector holds no
database handle at any point in its life.*

⚠ **K-3**: import is definitions only. Nothing below runs, opens or scans at
import time.
"""

from __future__ import annotations

from boundry_connector.refusal import Refusal, shown as _shown

import errno as _errno
import json
import os
import pathlib
import re
import stat as _stat
import sys
from dataclasses import dataclass
from typing import Any, Iterator

# ⚠ `K-3`: the label convention is IMPORTED from the one place that
# declares it, never restated here — and it is a SIBLING, so the shipped folder
# still runs on stdlib alone.
from .client_label import LabelRefused as _ClientLabelRefused    # noqa: E402
from .client_label import validate as _validate_client_label     # noqa: E402

__all__ = ["Record", "Corpus", "CorpusRefused", "ROOTS_ENV",
           "allowed_roots", "declared_roots", "label_of", "resolve_root",
           "DEMO_LABEL", "KIT_LABEL", "CORPUS_DIR_WORDING"]

#: ⚠ **THE REACH BOUND.**
#:
#: `SPEC…v0.2` §1's conversation-side rule — *everything rendered is governed as
#: if it may leave the machine, because it does* — is complete about the
#: RENDERING and silent about the REACH. **`corpus_dir` was unbounded, and it is
#: chosen by the MODEL, not by the operator**; when this was measured, the
#: connector read a file outside its own corpus and rendered its body into the
#: answer. A rule about how to treat what comes out does not bound what goes in.
#:
#: So the roots are DECLARED, and a path outside them REFUSES — the same shape
#: as `tenant_scope`: absence declares nothing, and the declaration is the
#: identity. Read at CALL time, never at import (`K-3`).
ROOTS_ENV = "BOUNDRY_CONNECTOR_ROOTS"


class CorpusRefused(Refusal):
    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


def _packaged_demo_root() -> pathlib.Path:
    return (pathlib.Path(__file__).resolve().parents[1] / "demo_corpus")


def _packaged_kit_root() -> pathlib.Path:
    """The evaluation kit's evidence: a second packaged root, beside the demo."""
    return (pathlib.Path(__file__).resolve().parents[1] / "kit_evidence")


#: ⚠⚠ **THE TWO PACKAGED ROOTS HAVE NAMES, AND THIS IS WHERE THEY ARE
#: DECLARED.** A reviewer installed the packed extension and drove it as Claude Desktop does: every tool
#: needs `corpus_dir`, `corpus_dir` took an absolute path, and with no folders configured those
#: roots sit inside the extension's install directory — which nothing tells the model or the
#: reader, because a refusal never renders a path. A reviewer following the listing's own example
#: prompts got `corpus-root-not-declared` on every call, and the package was unusable out of the
#: box while being, in every other respect, correct.
#:
#: > ***A DEFAULT NOBODY CAN ADDRESS IS NOT A DEFAULT. IT IS A SECRET.***
#:
#: The names are declared ONCE, here. The tool schemas, the server's instructions and the README
#: all DERIVE their sentence from this pair, so the thing a reviewer types and the thing that
#: resolves it cannot drift.
DEMO_LABEL = "demo"
KIT_LABEL = "kit"

#: The one sentence, built from the pair above. `tools.py`, `server.py` and the README read it.
CORPUS_DIR_WORDING = (
    "the label of a declared folder — with none configured, `%s` (the evaluation kit) or "
    "`%s` (the demonstration records) — or its full path." % (KIT_LABEL, DEMO_LABEL)
)


#: The marker a kernel export carries (`CONNECTOR/packaging/make_kit_evidence.py` writes it).
EXPORT_FORMAT = "boundry-kernel-export/1"


def _split_declaration(entry: str) -> tuple[str | None, pathlib.Path]:
    """`label=path` or a bare `path`.

    ⚠ **THE LABEL IS WHY THE QUESTION COULD BE ANSWERED AT ALL.** A Phase 3
    bundle carries **no subject identity** — measured on a real bundle, the
    closed field set is `bundle_version`, `checkpoint`, `inclusion_proof`,
    `key_directory_hint`, `receipts`, `record`, `witness_keys`, and not one of
    them names a client. So the connector cannot compare a root against the
    bundle. It can only compare **two declarations**: the label the operator put
    on the root, and the label the export wrote into its manifest.
    """
    if "=" in entry:
        label, _, path = entry.partition("=")
        label = label.strip()
        if label and path.strip():
            return label, pathlib.Path(path.strip()).expanduser().resolve()
    return None, pathlib.Path(entry.strip()).expanduser().resolve()


#: ⚠⚠ `F-116` (`ORDER_REV121`): **AN UNFILLED FIELD IS NOT A DECLARATION.** The manifest passes
#: `BOUNDRY_CONNECTOR_ROOTS: "${user_config.roots}"`, and with "Folders the connector may read" left
#: empty the host can hand that placeholder over unresolved. It was read as a bare path, the
#: packaged roots were REPLACED by it, and `kit` and `demo` both refused
#: `corpus-root-not-declared` — the release refused its own first prompt, installed as instructed.
#: An entry that is empty, whitespace only, or WHOLLY an unresolved `${...}` placeholder is
#: therefore not a root. A real entry still replaces the packaged roots, as it always did.
_UNRESOLVED_PLACEHOLDER = re.compile(r"^\$\{[^}]*\}$")


def _is_a_declaration(entry: str) -> bool:
    text = entry.strip()
    return bool(text) and not _UNRESOLVED_PLACEHOLDER.fullmatch(text)


def declared_roots() -> list[tuple[str | None, pathlib.Path]]:
    """`(label, path)` for every declared root, resolved at CALL time."""
    raw = os.environ.get(ROOTS_ENV, "")
    roots = [_split_declaration(e) for e in raw.split(os.pathsep) if _is_a_declaration(e)]
    return roots or [(DEMO_LABEL, _packaged_demo_root().resolve()),
                     (KIT_LABEL, _packaged_kit_root().resolve())]


def allowed_roots() -> list[pathlib.Path]:
    """The directories this connector may read, resolved at CALL time.

    `BOUNDRY_CONNECTOR_ROOTS` is a path-separator-delimited list the OPERATOR
    sets in the Claude Desktop config, each entry a bare path or `label=path`.
    **Unset means the two packaged synthetic roots — the demonstration corpus
    and the evaluation kit's evidence — and nothing else**.
    The safe default is the narrow one, which is the opposite of the default
    found in the auth stub.
    """
    return [path for _, path in declared_roots()]


def resolve_root(value: str | pathlib.Path) -> pathlib.Path:
    """a declared root's LABEL, or a path. Every reader goes through this.

    ⚠⚠ **A LABEL RESOLVES TO EXACTLY ONE DECLARED ROOT, OR IT IS NOT A LABEL.** The match is
    equality against the labels `declared_roots()` reports, and nothing else: no prefix, no
    case-folding, no completion. A value carrying a path separator is never read as a label, so
    `kit/../..` is a PATH and takes the path's refusal. A value that is not a declared label is
    also a path — `kitt` becomes a relative path, and `_check_reach` refuses it by name.
    Widening cannot enter here, because this function never returns anything but a root
    `declared_roots()` already named, or the caller's own value unchanged.
    """
    text = str(value)
    separators = {os.sep, os.altsep, "/"} - {None}
    if text and not any(sep in text for sep in separators):
        for label, root in declared_roots():
            if label is not None and text == label:
                return root
    return pathlib.Path(value)


def _label_for(target: pathlib.Path) -> str | None:
    """The label of the declared root containing `target`, if it carries one."""
    try:
        resolved = target.expanduser().resolve()
    except OSError:
        return None
    for label, root in declared_roots():
        if resolved == root or root in resolved.parents:
            return label
    return None


def label_of(target: str | pathlib.Path) -> str | None:
    """The declared label of the root containing `target`. **EXP-006's whole
    point: a tool renders this, never the path.**

    ⚠ It goes through `resolve_root` first, because two tools call this with the RAW
    `corpus_dir` argument. Without that, asking for `kit` by name answered `(unlabelled root)` —
    the tool would have resolved the label to read the records and then failed to name the root
    it had just read."""
    return _label_for(resolve_root(target))


def _within_a_declared_root(target: pathlib.Path) -> pathlib.Path | None:
    """The root containing `target`, or None. Resolved on BOTH sides, so a
    symlink or a `..` cannot walk out of a declared root."""
    try:
        resolved = target.expanduser().resolve()
    except OSError:
        return None
    for root in allowed_roots():
        if resolved == root or root in resolved.parents:
            return root
    return None


@dataclass(frozen=True)
class Record:
    """One sealed artefact as it sits on disk.

    `submitter_domain_ref` is the field the canon filter reads, spelled exactly
    as canon spells it, so `scope.apply_scope` can pass these straight to
    `_apply_tenant_scope` without a translation layer. *A translation layer
    between a boundary and its enforcement is a second place the rule lives.*
    """

    record_id: str
    submitter_domain_ref: str | None
    envelope_kind: str
    position: int
    body: dict[str, Any]
    content_hash: str | None
    signature_hex: str | None
    signing_key_id: str | None
    source_path: str

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "envelope_kind": self.envelope_kind,
            "position": self.position,
            "submitter_domain_ref": self.submitter_domain_ref,
            "content_hash": self.content_hash,
            "signing_key_id": self.signing_key_id,
        }


def _hex(value: Any, *, nullable: bool = False) -> bytes | None:
    """`bytes` for a hex string, `None` for an accepted null; raises ValueError otherwise."""
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        raise ValueError("not a string")
    return bytes.fromhex(value)


def _decodes(export: dict) -> bool:
    """The export's HEX fields decode, and each payload is a UTF-8
    JSON object — the format says so, and a reader that trusted it failed generically."""
    try:
        for env in export["envelopes"]:
            payload = _hex(env.get("payload_canonical_bytes"))
            if not isinstance(json.loads(payload.decode("utf-8")), dict):
                return False
            _hex(env.get("signature_bytes"))
            _hex(env.get("envelope_form_hash"))
            _hex(env.get("seal_signature"), nullable=True)
        for key, body in export["bodies"].items():
            if len(_hex(key)) != 32:
                return False
            _hex(body)
    except (ValueError, UnicodeDecodeError):
        return False
    return True


def classify_entry(doc: Any) -> str:
    """`record`, `export`, or the SHAPE of a JSON value that is neither."""
    if isinstance(doc, list):
        return "a top-level list"
    if not isinstance(doc, dict):
        return "a top-level scalar"
    if doc.get("export_format") == EXPORT_FORMAT:
        shaped = (isinstance(doc.get("run_id"), str) and isinstance(doc.get("signing_key_id"), str)
                  and isinstance(doc.get("bodies"), dict) and isinstance(doc.get("submitted_intent"), dict)
                  and isinstance(doc.get("envelopes"), list)
                  and all(isinstance(e, dict) for e in doc["envelopes"]))
        if not shaped:
            return "an export whose declared fields are missing or mis-shaped"
        return "export" if _decodes(doc) else "undecodable"
    if "export_format" in doc:
        return "an export in a format this reader does not declare"
    return "record" if "record_id" in doc else "an object with no record_id"


class Corpus:
    """A directory of sealed artefacts, opened read-only, held as bytes.

    **No handle is retained.** Files are read and closed; there is no cursor,
    no connection and no subscription. *`compiler/pipeline/envelope_emitter`'s
    `subscribe()` installs a live listener on a shared emitter — a read that
    leaves process state behind — and no tool here is built on it.*

    ⚠ The subscription half of that was prose alone until the
    sweep read it beside `tools.py`'s identical claim. Measured now by
    `test_G4_the_package_neither_WRITES_nor_SUBSCRIBES` (no `subscribe` call
    anywhere in the package) and `test_G4_the_emitter_is_not_IMPORTED_either`
    — **because a listener you never install but do import is one edit away.**
    """

    def __init__(self, root: str | pathlib.Path) -> None:
        # ⚠ ONE construction point, so a label is usable everywhere a path is — the seven
        # tools, the kit's readers, and anything added later — without a second resolution rule.
        self.root = resolve_root(root)

    def _check_client(self) -> None:
        """⚠ THE WRONG-CLIENT-ROOT REFUSAL, and it is a
        comparison of two DECLARATIONS, never a cryptographic binding.

        If the root carries a label AND a landed export left a manifest naming a
        client, the two must agree. **A mismatch means the operator pointed a
        client's root at another client's export**, which is the misconfiguration
        the work order asked to be constructed and refused.

        *What this does NOT do, said here because a reader will assume it does:
        it does not verify that the BUNDLE belongs to the named client. It
        cannot. The Phase 3 field set carries no subject identity, so nothing in
        the sealed bytes says whose record this is.*
        """
        label = _label_for(self.root)
        if label is None:
            return
        manifest = self.root / "EXPORT_MANIFEST.json"
        if not manifest.is_file():
            return
        try:
            declared = str(self._read_json(manifest).get("client_label", "")).strip()
        except CorpusRefused as _exc:
            # ⚠ Only a manifest that is not JSON is passed over, as
            # before. A manifest that is a LINK OUT OF THE ROOT is an attack on
            # the one comparison this method makes (`DEVB-2`), and
            # swallowing it would serve the records with the check skipped.
            if _exc.code != "corpus-record-unreadable":
                raise
            return
        # ⚠ A declaration that is not a well-formed label is
        # refused BEFORE it is compared. Comparing two malformed strings and
        # finding them equal would pass a name straight through the check that
        # exists to keep names out. The reach-bound rule stands unchanged — the
        # connector renders labels and never paths.
        for _l in (x for x in (declared, label) if x):
            try:
                _validate_client_label(_l)
            except _ClientLabelRefused as _exc:
                # ⚠ This RENDERED the malformed string in the sentence
                # that says it will not render it (attack `DEVB-11`).
                _which = ("the export's client_label" if _l == declared
                          else "this root's declared label")
                raise CorpusRefused(
                    "client-label-malformed",
                    f"{_which} is not a label under the convention "
                    f"({_exc.clause}). The connector refuses rather than "
                    f"rendering a string that may carry a client's name, and "
                    f"so it does not render it here")
        if declared and declared != label:
            raise CorpusRefused(
                "client-root-mismatch",
                f"this root is declared for client {label!r} and the export "
                f"that landed in it names client {declared!r}. Two declarations "
                "disagree, so the connector refuses rather than guess which is "
                "right. NOTE: this compares declarations only — a Phase 3 "
                "bundle carries no subject identity of its own")

    def _check_reach(self) -> None:
        """Refuse before opening anything outside a declared root."""
        if _within_a_declared_root(self.root) is None:
            raise CorpusRefused(
                "corpus-root-not-declared",
                "this connector reads only inside its declared roots and the "
                "folder you named is not one of them. You may name a declared "
                f"folder by its LABEL: with none configured those are "
                f"{KIT_LABEL!r} (the evaluation kit) and {DEMO_LABEL!r} (the "
                f"demonstration records). Set {ROOTS_ENV} in the Claude Desktop "
                "config to declare your own, as a path or as `label=path`. "
                "(The path is not echoed — in the practice's folder "
                "structure a client's path IS their name. Only the two PACKAGED "
                "labels are named here; a folder you declared is not listed back "
                "to you.)")

    # -- loading ---------------------------------------------------------
    def _named(self) -> str:
        """The root as a refusal may name it: its LABEL, never its path."""
        label = _label_for(self.root)
        return (f"the root labelled {label!r}" if label is not None
                else "this root (it carries no label, so none is shown)")

    def _confined_bytes(self, path: pathlib.Path) -> bytes:
        """⚠⚠ **THE ONE PLACE THIS CONNECTOR OPENS A
        FILE, AND EVERY BYTE IT READS COMES FROM INSIDE A DECLARED ROOT.**

        The root was checked; the ENTRIES in it were not. `glob("*.json")` and
        `root / "key_directory.json"` both follow a link, so a link placed in a
        declared folder made the connector read any file the user can read —
        an adversarial pass served an envelope from outside the root and opened `/etc/passwd`,
        and its own attacks took VERIFICATION KEYS from outside it
        (`DEVB-1`) and a forged client label (`DEVB-2`).

        **The rule, declared:** an entry is read only if its FINAL target —
        `os.path.realpath`, so a relative link and a chain of links are followed
        to the end — lies inside the resolved declared root. **A link that
        resolves INSIDE the root is ADMITTED**: it reads nothing the root does not
        already hold. A link that resolves outside is REFUSED with a code of its
        own, `corpus-entry-outside-root`, naming the root's LABEL and no path.

        ⚠ **THE RACE, NARROWED AND NAMED.** The resolved target is opened with
        `O_NOFOLLOW`, checked to be a REGULAR file on the open descriptor, and the
        entry is resolved AGAIN after opening: a different target, or a different
        file (device and inode) under the same name, refuses. What is left is a
        writer INSIDE the root swapping a name twice between two system calls.

        ⚠⚠ **A HARD LINK IS INVISIBLE TO `realpath`, SO IT HAS A RULE OF ITS OWN.**
        A hard link is a second NAME, inside the root, for a file whose other name
        may be anywhere on the same filesystem; there is no link to follow.
        Attack `DEVB-9` measured it: `realpath` containment alone SERVED a
        file whose other name was outside the root (same inode), before this fix
        and after the `realpath` half of it. So a regular file with MORE THAN ONE
        NAME (`st_nlink > 1`) is REFUSED, `corpus-entry-hard-linked`: nothing can
        say where its other names are. A record written by an export has one name;
        the cost is that a deliberately hard-linked record is refused, and says so.
        """
        root = _within_a_declared_root(self.root)
        if root is None:                    # _check_reach refused already
            raise CorpusRefused(
                "corpus-root-not-declared",
                "this connector reads only inside its declared roots")
        boundary = os.path.realpath(root)
        target = os.path.realpath(path)
        if not (target == boundary or target.startswith(boundary + os.sep)):
            raise CorpusRefused(
                "corpus-entry-outside-root",
                f"an entry in {self._named()} is a link whose target lies OUTSIDE "
                "that root, so it was not opened. This connector reads only "
                "inside its declared roots, and a link cannot widen one. (The "
                "entry's name and target are not echoed.)")
        flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0))
        try:
            fd = os.open(target, flags)
        except OSError as exc:
            raise CorpusRefused(
                "corpus-entry-unreadable",
                f"an entry in {self._named()} could not be opened "
                f"({_errno.errorcode.get(exc.errno, type(exc).__name__)})"
            ) from None
        try:
            opened = os.fstat(fd)
            if not _stat.S_ISREG(opened.st_mode):
                raise CorpusRefused(
                    "corpus-entry-not-a-file",
                    f"an entry in {self._named()} is named like a record but is "
                    "not a regular file, so it was not read")
            if opened.st_nlink > 1:
                raise CorpusRefused(
                    "corpus-entry-hard-linked",
                    f"an entry in {self._named()} is a file with "
                    f"{opened.st_nlink} names, so it was not read: a hard link "
                    "has no target to check, and its other names may lie outside "
                    "this root")
            again = os.path.realpath(path)
            try:
                now = os.stat(again)
            except OSError:
                now = None
            if (again != target or now is None
                    or (now.st_dev, now.st_ino) != (opened.st_dev, opened.st_ino)):
                raise CorpusRefused(
                    "corpus-entry-outside-root",
                    f"an entry in {self._named()} changed while it was being "
                    "opened, so it was not read")
            chunks = []
            while True:
                block = os.read(fd, 1 << 16)
                if not block:
                    return b"".join(chunks)
                chunks.append(block)
        except OSError as exc:
            raise CorpusRefused(
                "corpus-entry-unreadable",
                f"an entry in {self._named()} could not be read "
                f"({_errno.errorcode.get(exc.errno, type(exc).__name__)})"
            ) from None
        finally:
            os.close(fd)

    def _read_json(self, path: pathlib.Path) -> dict[str, Any]:
        raw = self._confined_bytes(path)    # read, and only read — and only inside
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CorpusRefused(
                "corpus-record-unreadable",
                f"a file in this root is not UTF-8 JSON ({type(exc).__name__})"
            ) from None

    def records(self) -> list[Record]:
        self._check_reach()
        self._check_client()
        if not self.root.is_dir():
            # ⚠ This read `no artefact directory at
            # {self.root}` — the ONE refusal the EXP-006 rule had not reached, and
            # the one the shipped echo check could not reach either.
            raise CorpusRefused(
                "corpus-root-absent",
                f"{self._named()} is declared but there is no directory at it; "
                "Stage 1 reads sealed artefacts from a directory and attaches to "
                "no live substrate. (A root is named by its LABEL and "
                "its path is not echoed.)")
        out: list[Record] = []
        for path, doc in self._classified():
            if doc.get("export_format") == EXPORT_FORMAT:
                continue                        # read by `exports()`, never as a record
            out.append(Record(
                record_id=str(doc["record_id"]),
                submitter_domain_ref=doc.get("submitter_domain_ref"),
                envelope_kind=str(doc.get("envelope_kind", "")),
                position=int(doc.get("position", 0)),
                body=doc.get("body") or {},
                content_hash=doc.get("content_hash"),
                signature_hex=doc.get("signature"),
                signing_key_id=doc.get("signing_key_id"),
                source_path=str(path.relative_to(self.root)),
            ))
        return out

    #: ⚠ The JSON files a root may hold that are not records, named ONE BY ONE: provisioning
    #: (`key_directory.json`), an export's own declaration (`EXPORT_MANIFEST.json`), and the
    #: kit's E5 result (`CONDUCT_LINE_RESULT.json`). Each has its own reader.
    NAMED_FILES = ("key_directory.json", "EXPORT_MANIFEST.json", "CONDUCT_LINE_RESULT.json")

    def _classified(self) -> list[tuple[pathlib.Path, dict[str, Any]]]:
        """⚠⚠ **EVERY JSON FILE IN A ROOT IS A RECORD, A KERNEL EXPORT,
        OR ONE OF `NAMED_FILES` — AND A FILE THAT IS NONE OF THEM REFUSES THE ROOT.**

         A measurement showed the cost of reading around it: a top-level list in a declared root
        raised `AttributeError` inside this loop, and every tool reading that root answered
        `tool-failed-unexpectedly` — honest, and naming nothing. The shape is now named,
        with the root's LABEL and no path (`EXP-006`).

        > ***A ROOT THAT HOLDS SOMETHING THE READER CANNOT NAME IS REFUSED FOR IT BY NAME,
        > NOT SERVED WITH THE FILE LEFT OUT.***

        Every reader of records and exports walks this one method, so the refusal holds for
        each tool that reads a root.
        """
        out = []
        for path in sorted(self.root.glob("*.json")):
            if path.name in self.NAMED_FILES:
                continue
            doc = self._read_json(path)
            shape = classify_entry(doc)
            if shape in ("record", "export"):
                out.append((path, doc))
                continue
            if shape == "undecodable":
                raise CorpusRefused(
                    "corpus-export-undecodable",
                    f"{self._named()} holds a kernel export whose fields are typed as declared but "
                    "whose contents do not decode: a hex field that is not hex, or a payload that is "
                    "not a UTF-8 JSON object. The root is refused rather than read around it. "
                    "(The root is named by its LABEL and no path is shown.)")
            raise CorpusRefused(
                "corpus-entry-not-a-record",
                f"{self._named()} holds a JSON file that is {shape}. A root holds records, "
                f"kernel exports and the files {list(self.NAMED_FILES)}; this file is "
                "none of them, so the root is refused rather than read around it. "
                "(The root is named by its LABEL and no path is shown.)")
        return out

    def exports(self) -> list[dict[str, Any]]:
        """The kernel exports in this root (`make_kit_evidence.py`'s format), by the same walk."""
        self._check_reach()
        self._check_client()
        if not self.root.is_dir():
            raise CorpusRefused(
                "corpus-root-absent",
                f"{self._named()} is declared but there is no directory at it. "
                "(A root is named by its LABEL and its path is not echoed.)")
        return [doc for _p, doc in self._classified() if doc.get("export_format") == EXPORT_FORMAT]

    def record(self, record_id: str) -> Record:
        for rec in self.records():
            if rec.record_id == record_id:
                return rec
        raise CorpusRefused(
            "corpus-record-absent",
            f"no record with id {_shown(record_id)} in this artefact directory")

    def key_directory(self) -> dict[str, str]:
        self._check_reach()
        self._check_client()
        path = self.root / "key_directory.json"
        if not path.is_file():
            return {}
        return {str(k): str(v) for k, v in self._read_json(path).items()}

    def __iter__(self) -> Iterator[Record]:
        return iter(self.records())
