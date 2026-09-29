"""The Stage-1 tool surface: five READ tools and one that refuses.

Stage 1: every function here is pure with respect to
the instance: it opens files for reading and returns a dict. **Nothing here
writes, signs, attaches to a database, subscribes to an emitter, or opens a
socket.**

⚠ **THAT SENTENCE MAKES FIVE CLAIMS AND FOR TWO OF THEM NOTHING EXISTED.** The
prose sweep read it as five: three were measured —
`test_the_package_cannot_sign`, `test_the_package_holds_no_database_handle`,
`test_the_package_imports_no_networking_of_any_kind` — and **writes** and
**subscribes to an emitter** were measured by nothing at all. Both were true
when checked, which is exactly why they were easy to miss.

> ***A TRUE CLAIM THAT NOTHING MEASURES IS STILL A CLAIM. THE SWEEP DOES NOT
> ASK WHETHER A SENTENCE IS TRUE; IT ASKS WHAT WOULD CATCH IT IF IT STOPPED
> BEING TRUE.***

The two gaps are now `test_G4_the_package_neither_WRITES_nor_SUBSCRIBES` and
`test_G4_the_emitter_is_not_IMPORTED_either`, each with a planted control, and
the STDIO transport's own `sys.stdout.write` is a NAMED exemption rather than a
silent skip.

⚠ **WHAT `verify_record` VERIFIES WITH, AND WHY IT IS NOT THE ENGINE.** It uses
the programme's INDEPENDENT verifier (`VERIFIER/boundry_verify`), written from
the ratified specifications by an author who had not read the kernel. Wrapping
the engine's own check would be the substrate confirming itself; the whole
value of the answer is that a second implementation agrees.

⚠ **THERE IS NO WRITE SURFACE HERE AT ALL** — not a disabled one, not a
refusing one. decided 's filed disagreement in favour of the
wall: the stub is gone from the listing and from the dispatcher.

⚠ **WHAT THE READ TOOLS DO NOT WRAP.** They do not wrap
`compiler/api/streaming.py`, which binds a principal and never uses it, and
they do not wrap `compiler/api/routes_replay.py`, whose catch-all reports any
artefact-store fault as `REPLAY_DIVERGENT` — an accusation where
`REPLAY_UNREACHABLE` is the honest outcome. Both are reported.
Rendering either into a chat window would put the substrate's own gaps in front
of the operator as findings about a record.
"""

from __future__ import annotations

import hashlib as _hashlib

import errno as _errno
import hashlib
import inspect as _inspect
import pathlib
import sys
from typing import Any

_PROGRAMME = pathlib.Path(__file__).resolve().parents[2]
if str(_PROGRAMME / "VERIFIER") not in sys.path:
    sys.path.insert(0, str(_PROGRAMME / "VERIFIER"))

from boundry_verify.canonical_form import canonical_bytes, content_hash  # noqa: E402
from boundry_verify.ed25519 import verify as ed25519_verify              # noqa: E402

from . import ladder                                                     # noqa: E402
from . import corpus                                                     # noqa: E402
from .corpus import Corpus, CorpusRefused                                # noqa: E402
from . import kit                                                        # noqa: E402
from .refusal import shown as _shown                                     # noqa: E402
from .scope import (PER_TENANT, ScopeRefused, apply_scope,
                    canon_filter_source)        # noqa: E402

__all__ = ["verify_record", "get_envelope", "query_envelopes",
           "chain_status", "explain_record", "check_plan_identity",
           "compare_runs", "TOOL_SCHEMAS",
           "TOOL_DESCRIPTION_DIGESTS", "dispatch"]

_VERIFIER_INSTRUMENT = (
    "VERIFIER/boundry_verify — the programme's INDEPENDENT verifier, written "
    "from the ratified specifications; canonical form per CF-ENC-001/CF-HASH-001, "
    "Ed25519 per RFC 8032 §5.1.7"
)


#: ⚠ **ONE WORDING FOR FIVE TOOLS**.
#: A measurement found `get_envelope` and `explain_record` identical in
#: `outcome`, `reason_code` and key set for out-of-scope, unscoped and absent —
#: but their `detail` strings were NOT identical: `get_envelope` carried the
#: second sentence and `explain_record` carried only the first. A caller
#: comparing whole responses could therefore tell the two tools apart, and with
#: them the question they were asked.
#:
#: > ***INDISTINGUISHABILITY THAT HOLDS FOR THE KEYS AND FAILS FOR THE PROSE IS
#: > NOT INDISTINGUISHABILITY; THE DETAIL IS A FIELD LIKE ANY OTHER.***
#:
#: The wording is defined once here and every tool serves exactly it.
def _not_in_scope_detail(record_id: str) -> str:
    # ⚠: `record_id` is client-supplied, and `"../../../etc/passwd"` was
    # echoed here — it was recorded as held, with the echo elided.
    # A plain id renders exactly as before, so ONE WORDING FOR FIVE TOOLS holds.
    return (f"no record {_shown(record_id)} within the declared scope. It may exist "
            "outside it; this answer says only that the scope you declared does "
            "not contain it.")


def _refusal(code: str, detail: str, *, instrument: str) -> dict:
    return {
        "outcome": "REFUSED",
        "reason_code": code,
        "detail": detail,
        "ladder": ladder.ladder_block(instrument=instrument, proven=[],
                                      attested=[]),
    }


# ---------------------------------------------------------------- verify ---
def verify_record(*, corpus_dir: str, record_id: str,
                  tenant_scope: str | None = None,
                  tenant_context: str | None = None) -> dict:
    """Four outcomes, and `UNATTESTED` never means the record is false.

    ⚠ **THIS TOOL TOOK NO SCOPE AND ANSWERED ABOUT ANY RECORD.**
    It returned
    `ATTESTED` for another tenant's record and handed back `record` =
    `rec.summary` — six keys **including `submitter_domain_ref`, naming the
    tenant the record belongs to** — while `get_envelope` and `explain_record`
    declined to say whether that same id existed at all.

    > ***A VERDICT ON A RECORD THE CALLER CANNOT SEE IS A DISCLOSURE, AND IT
    > DISCLOSES MORE THAN THE TOOL THAT REFUSED TO SHOW IT.***

    It now takes `tenant_scope` and `tenant_context` exactly as the other three
    do — absence REFUSES, `global` is a declared scope, `per_tenant` without a
    context refuses — and the record is looked up **inside the declared scope**,
    so out-of-scope and absent collapse into one answer with the same four keys
    and the same wording every other tool serves. `ATTESTED`, `REFUTED`,
    `ALTERED` and `UNATTESTED` are reachable only for a record inside the scope.
    """
    try:
        rows = _scoped(corpus_dir, tenant_scope, tenant_context)
        keys = Corpus(corpus_dir).key_directory()
    except (ScopeRefused, CorpusRefused) as exc:
        return _refusal(exc.code, exc.detail, instrument=_SCOPE_INSTRUMENT)

    match = [r for r in rows if r.record_id == record_id]
    if not match:
        # ⚠ the SAME refusal `get_envelope` and `explain_record` serve, so an
        # id that is another tenant's and an id that does not exist are one
        # answer. This is the whole 's first limb.
        return _refusal("envelope-not-in-scope",
                        _not_in_scope_detail(record_id),
                        instrument=_SCOPE_INSTRUMENT)
    rec = match[0]

    canon = canonical_bytes(rec.body)
    recomputed = hashlib.sha256(canon).hexdigest()
    proven: list[str] = [
        f"the record's body canonicalises to {len(canon)} bytes under "
        f"CF-ENC-001 and hashes to {recomputed}",
    ]

    if rec.content_hash is not None and recomputed != rec.content_hash:
        return {
            "outcome": "ALTERED",
            "reason_code": "content-hash-mismatch",
            "detail": (f"the body hashes to {recomputed}; the record declares "
                       f"{rec.content_hash}. The bytes are not the bytes that "
                       "were recorded for them."),
            "record": rec.summary,
            "verdict_means": ladder.VERDICT_MEANINGS["ALTERED"],
            "ladder": ladder.ladder_block(
                instrument=_VERIFIER_INSTRUMENT, proven=proven,
                attested=["nothing: the signature was not evaluated, because "
                          "what it covers is already known not to be present"]),
        }
    if rec.content_hash is not None:
        proven.append("the declared content_hash matches the recomputed one")

    if rec.signature_hex is None or rec.signing_key_id is None:
        return {
            "outcome": "UNATTESTED",
            "reason_code": "no-signature-on-record",
            "detail": ("this record carries no signature, so nothing was "
                       "evaluated about who sealed it. This is a gap in the "
                       "EVIDENCE, not a finding against the record."),
            "record": rec.summary,
            "verdict_means": ladder.VERDICT_MEANINGS["UNATTESTED"],
            "ladder": ladder.ladder_block(instrument=_VERIFIER_INSTRUMENT,
                                          proven=proven, attested=[]),
        }
    key_hex = keys.get(rec.signing_key_id)
    if key_hex is None:
        return {
            "outcome": "UNATTESTED",
            "reason_code": "signing-key-not-provisioned",
            "detail": (f"the record is signed under key {rec.signing_key_id!r} "
                       "and this reader was not provisioned with it. The check "
                       "never ran; absence of the means to evaluate is never "
                       "refutation."),
            "record": rec.summary,
            "verdict_means": ladder.VERDICT_MEANINGS["UNATTESTED"],
            "ladder": ladder.ladder_block(instrument=_VERIFIER_INSTRUMENT,
                                          proven=proven, attested=[]),
        }

    ok = ed25519_verify(bytes.fromhex(key_hex), canon,
                        bytes.fromhex(rec.signature_hex))
    if not ok:
        return {
            "outcome": "REFUTED",
            "reason_code": "signature-does-not-verify",
            "detail": ("the signature does not verify over the record's own "
                       "canonical bytes under the provisioned key. Evidence "
                       "was supplied and it failed."),
            "record": rec.summary,
            "verdict_means": ladder.VERDICT_MEANINGS["REFUTED"],
            "ladder": ladder.ladder_block(instrument=_VERIFIER_INSTRUMENT,
                                          proven=proven, attested=[]),
        }
    return {
        "outcome": "ATTESTED",
        "reason_code": "signature-verifies-under-provisioned-key",
        "detail": ("the signature verifies over the record's canonical bytes "
                   "under the key this reader was provisioned with."),
        "record": rec.summary,
        "verdict_means": ladder.VERDICT_MEANINGS["ATTESTED"],
        "ladder": ladder.ladder_block(
            instrument=_VERIFIER_INSTRUMENT, proven=proven,
            attested=[f"that the holder of key {rec.signing_key_id!r} sealed "
                      "these exact bytes — and nothing about WHEN, because no "
                      "witness and no timestamp authority was consulted"]),
    }


# ------------------------------------------------------------- envelopes ---
def _scoped(corpus_dir: str, tenant_scope: str | None,
            tenant_context: str | None):
    rows = Corpus(corpus_dir).records()
    return apply_scope(rows, tenant_scope=tenant_scope,
                       tenant_context=tenant_context)


_SCOPE_INSTRUMENT = (
    "compiler.stages.tenant_scope._apply_tenant_scope — canon's ONE "
    "enforcement site, imported and not re-typed"
)


def get_envelope(*, corpus_dir: str, record_id: str,
                 tenant_scope: str | None = None,
                 tenant_context: str | None = None) -> dict:
    """One envelope, tenant-scoped. Absence of scope REFUSES."""
    try:
        rows = _scoped(corpus_dir, tenant_scope, tenant_context)
    except (ScopeRefused, CorpusRefused) as exc:
        return _refusal(exc.code, exc.detail, instrument=_SCOPE_INSTRUMENT)
    for rec in rows:
        if rec.record_id == record_id:
            return {
                "outcome": "OK",
                "envelope": {**rec.summary, "body": rec.body,
                             "source_path": rec.source_path},
                "ladder": ladder.ladder_block(
                    instrument=_SCOPE_INSTRUMENT,
                    proven=[f"this row was inside tenant_scope={tenant_scope!r}"
                            + (f", tenant_context={tenant_context!r}"
                               if tenant_context else "")],
                    tenant_scoped=True),
            }
    return _refusal("envelope-not-in-scope",
                    _not_in_scope_detail(record_id),
                    instrument=_SCOPE_INSTRUMENT)


def query_envelopes(*, corpus_dir: str, tenant_scope: str | None = None,
                    tenant_context: str | None = None,
                    envelope_kind: str | None = None,
                    limit: int = 50) -> dict:
    """Envelopes in scope. Absence of scope REFUSES rather than returning the union."""
    try:
        rows = _scoped(corpus_dir, tenant_scope, tenant_context)
    except (ScopeRefused, CorpusRefused) as exc:
        return _refusal(exc.code, exc.detail, instrument=_SCOPE_INSTRUMENT)
    if envelope_kind is not None:
        rows = [r for r in rows if r.envelope_kind == envelope_kind]
    total = len(rows)
    rows = rows[: max(0, int(limit))]
    return {
        "outcome": "OK",
        "count_returned": len(rows),
        "count_in_scope": total,
        "envelopes": [r.summary for r in rows],
        "ladder": ladder.ladder_block(
            instrument=_SCOPE_INSTRUMENT,
            proven=[f"{total} rows were inside the declared scope; "
                    f"{len(rows)} returned under limit={limit}"],
            attested=[],
            tenant_scoped=True),
    }


# ----------------------------------------------------------- chain status ---
def chain_status(*, corpus_dir: str, tenant_scope: str | None = None,
                 tenant_context: str | None = None) -> dict:
    """Figures with the instrument named beside each one.

    ⚠ There is no live chain here and this says so. The specification asks for "head,
    era, manifest seq, sweep figures with the instrument named"; what a
    non-attaching reader can honestly produce is the artefact directory's own
    head and the digests of the registers it read. **A figure this build cannot
    take is reported as NOT TAKEN, with the reason, rather than omitted** —
    an absent figure and a zero figure are different facts.
    """
    # ⚠ **THIS TOOL RETURNED THE WHOLE CORPUS'S FIGURES TO ANY CALLER.**
    # `tenants_present`
    # named every tenant in the directory and `unscoped_rows` counted rows
    # belonging to nobody, with no `tenant_scope` parameter to constrain either —
    # while its own ladder block claimed `tenant_scoped=True`.
    #
    # > ***A LADDER THAT CLAIMS A SCOPE THE TOOL HAS NO PARAMETER FOR IS NOT A
    # > WEAK CLAIM; IT IS A FALSE ONE, AND IT IS IN THE EVIDENCE BLOCK.***
    #
    # It now takes the scope the other four take, and every figure below is a
    # figure OF THE DECLARED SCOPE.
    try:
        rows = _scoped(corpus_dir, tenant_scope, tenant_context)
    except (ScopeRefused, CorpusRefused) as exc:
        return _refusal(exc.code, exc.detail, instrument=_SCOPE_INSTRUMENT)
    ordered = sorted(rows, key=lambda r: (r.submitter_domain_ref or "", r.position))
    head = ordered[-1].record_id if ordered else None
    tenants = sorted({r.submitter_domain_ref for r in rows
                      if r.submitter_domain_ref is not None})
    scoped_view = tenant_scope == PER_TENANT
    body: dict[str, Any] = {
        "outcome": "OK",
        # ⚠ EXP-006 — LABELS, NEVER PATHS. This returned `str(corpus_dir)`
        # until. In the practice's folder structure a client's path is
        # their NAME, and named the open route: not a record
        # reaching canon, but a client's name arriving inside a figure somebody
        # pasted into a report. **A path is configuration; it is not output.**
        "root_label": corpus.label_of(corpus_dir) or "(unlabelled root)",
        "records_present": len(rows),
        "head_record_id": head,
        "figures": [
            {"figure": "records_present", "value": len(rows),
             "instrument": "CONNECTOR/boundry_connector/corpus.py — a sorted "
                           "glob of *.json opened 'rb', no database handle held"},
            {"figure": "tenant enforcement site", "value": canon_filter_source(),
             "instrument": "inspect.getsourcefile on the imported filter"},
        ],
        "not_taken": [
            {"figure": "chain head hash / era / manifest sequence",
             "reason": ("Stage 1 attaches to no live substrate, because every "
                        "substrate connection in canon is read-write and "
                        "attaching would itself be a write. These figures need "
                        "an instance; this reader has an artefact directory.")},
            {"figure": "witness / timestamp status",
             "reason": "nothing was contacted; no witness was consulted."},
        ],
        "ladder": ladder.ladder_block(
            instrument="CONNECTOR/boundry_connector/chain_status",
            proven=[f"{len(rows)} artefacts were read from disk inside "
                    f"tenant_scope={tenant_scope!r}"
                    + (f", tenant_context={tenant_context!r}"
                       if tenant_context else "")],
            attested=[], tenant_scoped=True),
    }
    # ⚠ UNDER `per_tenant` THE TWO CROSS-TENANT KEYS ARE ABSENT, NOT EMPTIED.
    # An empty `tenants_present` would be a claim that the caller's scope
    # contains no tenants; the key's ABSENCE says the figure is not one this
    # scope can produce, which is `chain_status`'s own `not_taken` discipline —
    # *an absent figure and a zero figure are different facts* — applied to
    # scope rather than to a missing substrate.
    if not scoped_view:
        body["tenants_present"] = tenants
        body["unscoped_rows"] = sum(1 for r in rows
                                    if r.submitter_domain_ref is None)
    else:
        body["not_taken"] = list(body["not_taken"]) + [
            {"figure": "tenants_present / unscoped_rows",
             "reason": ("these are figures ABOUT other tenants and about rows "
                        "belonging to none; under per_tenant they are not this "
                        "caller's to have. Under a declared global scope they "
                        "are served as before.")},
        ]
    return body


# ---------------------------------------------------------------- explain ---
def explain_record(*, corpus_dir: str, record_id: str,
                   tenant_scope: str | None = None,
                   tenant_context: str | None = None) -> dict:
    """Provenance rendered FROM ARTEFACTS, never from memory.

    Every line below is derived from bytes read in this call. Nothing is
    recalled, inferred from a name, or supplied by the model.
    """
    try:
        rows = _scoped(corpus_dir, tenant_scope, tenant_context)
    except (ScopeRefused, CorpusRefused) as exc:
        return _refusal(exc.code, exc.detail, instrument=_SCOPE_INSTRUMENT)
    match = [r for r in rows if r.record_id == record_id]
    if not match:
        try:
            exports, keys = _scoped_exports(corpus_dir, tenant_scope, tenant_context)
        except (ScopeRefused, CorpusRefused) as exc:
            return _refusal(exc.code, exc.detail, instrument=_SCOPE_INSTRUMENT)
        run = [e for e in exports if e["run_id"] == record_id]
        if run:
            return _explain_export(run[0], keys)
        return _refusal(
            "envelope-not-in-scope",
            _not_in_scope_detail(record_id),
            instrument=_SCOPE_INSTRUMENT)
    rec = match[0]
    # ⚠ THE SCOPE IS PASSED THROUGH. `verify_record` now refuses on an
    # absent scope, so a scoped tool delegating to it without its own scope
    # would refuse its own in-scope record — the coupling the parameter created.
    verdict = verify_record(corpus_dir=corpus_dir, record_id=record_id,
                            tenant_scope=tenant_scope,
                            tenant_context=tenant_context)
    siblings = [r.record_id for r in rows
                if r.submitter_domain_ref == rec.submitter_domain_ref
                and r.record_id != rec.record_id]
    story = [
        f"Read from record {rec.record_id!r} in the root labelled "
        f"{corpus.label_of(corpus_dir) or '(unlabelled)'!r}.",
        f"It declares tenant {rec.submitter_domain_ref!r} and position "
        f"{rec.position} in kind {rec.envelope_kind!r}.",
        f"Its body canonicalises under CF-ENC-001 and the independent verifier "
        f"returns {verdict['outcome']}: {verdict['detail']}",
        (f"{len(siblings)} other record(s) in the same tenant were visible in "
         f"the scope you declared: {siblings}" if siblings else
         "No other record of this tenant was inside the scope you declared."),
    ]
    return {
        "outcome": "OK",
        "record": rec.summary,
        "provenance": story,
        "verification": verdict,
        "sources_read": ["the record's own file", "key_directory.json"],
        "ladder": ladder.ladder_block(
            instrument=_VERIFIER_INSTRUMENT,
            proven=["every line of `provenance` was derived from bytes read "
                    "during this call; nothing was recalled from memory"],
            attested=[], tenant_scoped=True),
    }


# ------------------------------------------------------------- dispatch ----
#: Descriptions are EXTERNAL WORDING (LEAK-2) — no strong forms.
#: ⚠ **EVERY TOOL DECLARES WHAT IT IS, AND THE DECLARATION IS PINNED.**
#: All five carry `annotations` — a `title` and MCP's four hints.
#: The values are the same for all five because the surface is: `readOnlyHint`
#: true, `destructiveHint` false, `idempotentHint` true, `openWorldHint` false.
#:
#: `openWorldHint` is **false** and that is a measured choice, not a default: a
#: tool here reads a DECLARED local artefact directory and reaches nothing
#: beyond it — no network (`test_the_package_imports_no_networking_of_any_kind`)
#: and no substrate (`test_the_package_holds_no_database_handle`). A true
#: `openWorldHint` would tell a model this surface may reach anywhere, which is
#: the opposite of what the roots and the scope seam enforce.
#:
#: ⚠ **A HINT IS A CLAIM A MODEL READS BEFORE IT ACTS, SO IT IS PINNED BY VALUE
#: AND NOT BY DIGEST.** `TOOL_DESCRIPTION_DIGESTS` hashes free text, where no
#: assertion can state the content; these five keys are booleans and a title, so
#: `test_G2_*` asserts them EXACTLY. A digest would say a hint moved; the vector
#: says which way it was supposed to point.
#:
#: > ***A `readOnlyHint` THAT NOTHING PINS IS A PROMISE TO THE MODEL THAT ONLY
#: > THE CODE REMEMBERS.***
#:
#: The digests do not move: they hash `description` alone, and no description is
#: touched here, so no register act falls out of this change.
# ------------------------------------------------------ the evaluation kit ---
#: The kit's two tools, and `explain_record`'s walk of an export. Each reads a
#: root through `Corpus` (the one confined opener, ), under the one scope rule, and renders
#: identifiers, hashes and the record's own words — a path is not among them.
_KIT_INSTRUMENT = (
    "boundry_connector.kit over VERIFIER/boundry_verify — CF-ENC-001 canonical form, RFC 8032 "
    "Ed25519, the v3 envelope form; the kernel is not imported")


class _ScopedRun:
    """What `apply_scope` reads of an export: its id and the tenant its record states."""

    def __init__(self, export: dict) -> None:
        self.export = export
        self.record_id = export["run_id"]
        self.submitter_domain_ref = kit.domain_of(export)


def _scoped_exports(corpus_dir: str, tenant_scope: str | None,
                    tenant_context: str | None) -> tuple[list[dict], dict[str, str]]:
    root = Corpus(corpus_dir)
    runs = apply_scope([_ScopedRun(e) for e in root.exports()],
                       tenant_scope=tenant_scope, tenant_context=tenant_context)
    return [r.export for r in runs], root.key_directory()


def _key_for(export: dict, keys: dict[str, str]) -> str | None:
    return keys.get(str(export.get("signing_key_id")))


def _unprovisioned(export: dict) -> dict:
    return _refusal("kit-signing-key-not-provisioned",
                    f"run {_shown(export['run_id'])} names a signing key id this root's "
                    "key_directory.json does not provision, so its signatures were not checked. "
                    "This states a gap in the reader, not a finding against the run.",
                    instrument=_KIT_INSTRUMENT)


def check_plan_identity(*, corpus_dir: str, run_id: str,
                        tenant_scope: str | None = None,
                        tenant_context: str | None = None) -> dict:
    """E1: recompute a sealed plan's id offline, and check its seal."""
    try:
        exports, keys = _scoped_exports(corpus_dir, tenant_scope, tenant_context)
    except (ScopeRefused, CorpusRefused) as exc:
        return _refusal(exc.code, exc.detail, instrument=_SCOPE_INSTRUMENT)
    run = [e for e in exports if e["run_id"] == run_id]
    if not run:
        return _refusal("envelope-not-in-scope", _not_in_scope_detail(run_id),
                        instrument=_SCOPE_INSTRUMENT)
    key = _key_for(run[0], keys)
    if key is None:
        return _unprovisioned(run[0])
    ident = kit.identity(run[0], key)
    if ident is None:
        return _refusal("run-sealed-no-plan",
                        f"run {_shown(run_id)} sealed no plan: its record ends in a refusal, "
                        "which explain_record reads.", instrument=_KIT_INSTRUMENT)
    return {
        "outcome": "OK",
        "verdict": "HOLDS" if ident["holds"] else "FAILS",
        "run_id": run_id,
        "micro_contract_id": ident["micro_contract_id"],
        "content_hash": ident["content_hash"],
        "fields_used": ident["fields_used"],
        "checks": ident["checks"],
        "what_the_id_identifies": kit.F87_STATEMENT,
        "ladder": ladder.ladder_block(instrument=_KIT_INSTRUMENT,
                                      proven=[c["check"] for c in ident["checks"] if c["holds"]]),
    }


def compare_runs(*, corpus_dir: str, run_id_a: str, run_id_b: str,
                 tenant_scope: str | None = None,
                 tenant_context: str | None = None) -> dict:
    """E2/E3: two runs, each against its own record, then field by field."""
    try:
        exports, keys = _scoped_exports(corpus_dir, tenant_scope, tenant_context)
    except (ScopeRefused, CorpusRefused) as exc:
        return _refusal(exc.code, exc.detail, instrument=_SCOPE_INSTRUMENT)
    by_id = {e["run_id"]: e for e in exports}
    for rid in (run_id_a, run_id_b):
        if rid not in by_id:
            return _refusal("envelope-not-in-scope", _not_in_scope_detail(rid),
                            instrument=_SCOPE_INSTRUMENT)
    a, b = by_id[run_id_a], by_id[run_id_b]
    key = _key_for(a, keys)
    if key is None or _key_for(b, keys) != key:
        return _unprovisioned(a if key is None else b)
    got = kit.compare(a, b, key)
    return {
        "outcome": "OK",
        "verdict": got["verdict"],
        "run_a": dict(got["run_a"], run_id=run_id_a),
        "run_b": dict(got["run_b"], run_id=run_id_b),
        "differences": got["differences"],
        "what_this_is": ("hash comparison over two records and the bytes they name. It is "
                         "not re-execution: E3 detects tampering after the fact, and E2's "
                         "claim rests on two independent runs being compared here."),
        "ladder": ladder.ladder_block(instrument=_KIT_INSTRUMENT,
                                      proven=[f"{run_id_a}: {got['run_a']['verdict']}",
                                              f"{run_id_b}: {got['run_b']['verdict']}"]),
    }


def _explain_export(export: dict, keys: dict[str, str]) -> dict:
    """E6 and E4: an export's lineage, link by link, or its refusal record."""
    key = _key_for(export, keys)
    if key is None:
        return _unprovisioned(export)
    links = kit.lineage(export, key)
    return {
        "outcome": "OK",
        "record_kind": "kernel-export",
        "run_id": export["run_id"],
        "lineage": links,
        "holds": all(link["holds"] for link in links),
        "sources_read": ["the export's own file", "key_directory.json"],
        "ladder": ladder.ladder_block(instrument=_KIT_INSTRUMENT,
                                      proven=[link["check"] for link in links if link["holds"]]),
    }


#: ⚠⚠ **THE ONE THING A REVIEWER HAS TO TYPE, SAID IN THE SCHEMA.**
#: Every tool takes `corpus_dir`, and it took an absolute path. With no folders configured the
#: only readable roots are inside the extension's install directory, which nothing told the model
#: and no refusal may render. A reviewer installed the packed extension and every example prompt in the
#: listing came back `corpus-root-not-declared`.
#:
#: The sentence is DERIVED from `corpus.CORPUS_DIR_WORDING`, which is built from the two label
#: declarations, so the schema a model reads, the instructions it is given and the README a human
#: reads cannot disagree with what actually resolves.
_CORPUS_DIR_DESCRIPTION = "corpus_dir: " + corpus.CORPUS_DIR_WORDING


TOOL_SCHEMAS: tuple[dict[str, Any], ...] = (
    {"name": "verify_record",
     "annotations": {"title": "Verify a sealed record",
                     "readOnlyHint": True, "destructiveHint": False,
                     "idempotentHint": True, "openWorldHint": False},
     "description": ("Check one sealed record with Boundry's INDEPENDENT "
                     "verifier and report one of four outcomes: ATTESTED, "
                     "REFUTED, ALTERED, UNATTESTED. UNATTESTED states a gap in "
                     "the reader and is never a finding against the record. "
                     "tenant_scope is REQUIRED — omitting it refuses rather "
                     "than verifying any record in the directory. A tool "
                     "answers only inside the declared scope."),
     "inputSchema": {"type": "object",
                     "required": ["corpus_dir", "record_id", "tenant_scope"],
                     "properties": {"corpus_dir": {"type": "string"},
                                    "record_id": {"type": "string"},
                                    "tenant_scope": {"type": "string",
                                                     "enum": ["global", "per_tenant"]},
                                    "tenant_context": {"type": "string"}}}},
    {"name": "get_envelope",
     "annotations": {"title": "Read one envelope",
                     "readOnlyHint": True, "destructiveHint": False,
                     "idempotentHint": True, "openWorldHint": False},
     "description": ("Read one envelope. tenant_scope is REQUIRED — omitting it "
                     "refuses rather than returning everything. A tool answers only inside the "
                     "declared scope."),
     "inputSchema": {"type": "object",
                     "required": ["corpus_dir", "record_id", "tenant_scope"],
                     "properties": {"corpus_dir": {"type": "string"},
                                    "record_id": {"type": "string"},
                                    "tenant_scope": {"type": "string",
                                                     "enum": ["global", "per_tenant"]},
                                    "tenant_context": {"type": "string"}}}},
    {"name": "query_envelopes",
     "annotations": {"title": "List envelopes in the declared scope",
                     "readOnlyHint": True, "destructiveHint": False,
                     "idempotentHint": True, "openWorldHint": False},
     "description": ("List envelopes within a declared scope. tenant_scope is "
                     "REQUIRED — absence of identity is not omniscience. A tool answers only inside the "
                     "declared scope."),
     "inputSchema": {"type": "object",
                     "required": ["corpus_dir", "tenant_scope"],
                     "properties": {"corpus_dir": {"type": "string"},
                                    "tenant_scope": {"type": "string",
                                                     "enum": ["global", "per_tenant"]},
                                    "tenant_context": {"type": "string"},
                                    "envelope_kind": {"type": "string"},
                                    "limit": {"type": "integer"}}}},
    {"name": "chain_status",
     "annotations": {"title": "Report what this reader can see",
                     "readOnlyHint": True, "destructiveHint": False,
                     "idempotentHint": True, "openWorldHint": False},
     "description": ("Report what this reader can see of an artefact directory, "
                     "each figure naming the instrument that produced it, and "
                     "each figure it could NOT take named as not taken. "
                     "tenant_scope is REQUIRED. Under per_tenant every figure "
                     "is a figure of the declared scope and the cross-tenant "
                     "figures are absent, not emptied. A tool answers only "
                     "inside the declared scope."),
     "inputSchema": {"type": "object",
                     "required": ["corpus_dir", "tenant_scope"],
                     "properties": {"corpus_dir": {"type": "string"},
                                    "tenant_scope": {"type": "string",
                                                     "enum": ["global", "per_tenant"]},
                                    "tenant_context": {"type": "string"}}}},
    {"name": "explain_record",
     "annotations": {"title": "Explain one record's provenance",
                     "readOnlyHint": True, "destructiveHint": False,
                     "idempotentHint": True, "openWorldHint": False},
     "description": ("Render one record's provenance from the artefacts read "
                     "during the call. Nothing is recalled from memory. A tool answers only inside the "
                     "declared scope."),
     "inputSchema": {"type": "object",
                     "required": ["corpus_dir", "record_id", "tenant_scope"],
                     "properties": {"corpus_dir": {"type": "string"},
                                    "record_id": {"type": "string"},
                                    "tenant_scope": {"type": "string",
                                                     "enum": ["global", "per_tenant"]},
                                    "tenant_context": {"type": "string"}}}},
    {"name": "check_plan_identity",
     "annotations": {"title": "Recompute a sealed plan's identity",
                     "readOnlyHint": True, "destructiveHint": False,
                     "idempotentHint": True, "openWorldHint": False},
     "description": ("Recompute a sealed plan's id from its six inputs and check its seal, "
                     "from a kernel export in a declared root. The id identifies the six "
                     "inputs; the plan body is identified by the seal's content_hash. "
                     "tenant_scope is REQUIRED. A tool answers only inside the declared scope."),
     "inputSchema": {"type": "object",
                     "required": ["corpus_dir", "run_id", "tenant_scope"],
                     "properties": {"corpus_dir": {"type": "string"},
                                    "run_id": {"type": "string"},
                                    "tenant_scope": {"type": "string",
                                                     "enum": ["global", "per_tenant"]},
                                    "tenant_context": {"type": "string"}}}},
    {"name": "compare_runs",
     "annotations": {"title": "Compare two runs field by field",
                     "readOnlyHint": True, "destructiveHint": False,
                     "idempotentHint": True, "openWorldHint": False},
     "description": ("Check two kernel exports against their own records, then compare them "
                     "field by field and name each difference: EQUIVALENT, DIVERGENT or "
                     "UNREACHABLE. This is hash comparison, not re-execution. tenant_scope is "
                     "REQUIRED. A tool answers only inside the declared scope."),
     "inputSchema": {"type": "object",
                     "required": ["corpus_dir", "run_id_a", "run_id_b", "tenant_scope"],
                     "properties": {"corpus_dir": {"type": "string"},
                                    "run_id_a": {"type": "string"},
                                    "run_id_b": {"type": "string"},
                                    "tenant_scope": {"type": "string",
                                                     "enum": ["global", "per_tenant"]},
                                    "tenant_context": {"type": "string"}}}},
)

_DISPATCH = {
    "verify_record": verify_record,
    "get_envelope": get_envelope,
    "query_envelopes": query_envelopes,
    "chain_status": chain_status,
    "explain_record": explain_record,
    "check_plan_identity": check_plan_identity,
    "compare_runs": compare_runs,
}


def dispatch(name: str, arguments: dict[str, Any]) -> dict:
    """Call one tool by name. An unknown name REFUSES; it never guesses."""
    fn = _DISPATCH.get(name)
    if fn is None:
        return _refusal("tool-not-registered",
                        f"this server registers {sorted(_DISPATCH)}; "
                        f"{_shown(name)} is not among them",
                        instrument="CONNECTOR/boundry_connector/tools.py")
    # ⚠: this rendered `str(exc)` of the TypeError, which quotes the
    # argument NAME the client sent — a planted path came back verbatim (
    # `DEVB-10`). The arguments are now BOUND first, and the refusal names the
    # tool's own declared parameters, which are the server's words, not the
    # client's. A TypeError raised INSIDE a tool is no longer mistaken for one.
    params = sorted(_inspect.signature(fn).parameters)
    try:
        _inspect.signature(fn).bind(**arguments)
    except TypeError:
        return _refusal("tool-arguments-rejected",
                        f"the arguments given do not match {name}'s declared "
                        f"parameters {params}: one is missing or not accepted. "
                        "(The arguments given are not echoed: a refusal never "
                        "renders client-supplied text.)",
                        instrument="CONNECTOR/boundry_connector/tools.py")
    try:
        return fn(**arguments)
    except Exception as exc:
        # ⚠. Two rendering paths escaped the conversation-side
        # rule: a raw interpreter message, and — worse — an UNCAUGHT exception,
        # which reached no payload at all and took the server down with it.
        # **Every answer this connector gives now carries a ladder**, including
        # the ones nobody planned. The exception TYPE is named and its text is
        # bounded; a traceback is not conversation content.
        return _refusal(
            "tool-failed-unexpectedly",
            # ⚠: the exception's TEXT is no longer rendered at all. An
            # `OSError`'s text carries the full path it failed on (
            # `DEVB-6`, `DEVB-7` echoed the scratch path verbatim), and nothing
            # a caller needs is in it that the type and the errno do not say.
            f"{type(exc).__name__}"
            + (f" ({_errno.errorcode.get(exc.errno, '?')})"
               if isinstance(exc, OSError) and exc.errno else "")
            + ". This states a fault in the connector, NOT a finding about any "
            "record. (Its message is not rendered: it may carry a path.)",
            instrument="CONNECTOR/boundry_connector/tools.py")


#: ⚠ **THE SENTENCES A MODEL READS BEFORE EVERY TURN, GOVERNED BY DIGEST**
#: ( V4, ). ⚠ **STILL TRUE AT `231f30a`, AND NOW MEASURED:**
#: `TOOL_SCHEMAS` is a tuple of DICTS, outside all five `RECOGNISED_SHAPES`, so
#: `vocabulary_sweep` skips it SILENTLY —
#: `test_G4_TOOL_SCHEMAS_is_invisible_to_the_sweep_and_the_DIGESTS_are_not`
#: asserts exactly that, and fires if the shapes are ever widened to reach it.
#:
#: **PAST, and it is past because repaired it:** the register once
#: governed the tool NAMES while the descriptions travelled ungoverned. The
#: register recorded that as a gap and left widening the shapes to RESEARCH.
#:
#: **This closes it without widening anything**: a flat `{name: sha256}` map is
#: an ordinary registrable shape, so the sentences become drift-detectable under
#: the rules already in force. ⚠ **DERIVED FROM `TOOL_SCHEMAS` AT IMPORT, never
#: typed** — a hand-copied digest would be stale the first time a sentence was
#: edited, which is the whole failure it exists to catch (`COUNT-002`).
#:
#: ⚠ **A DIGEST IS NOT A REVIEW.** It says the sentence changed, not that the
#: new one is honest. What a tool description claims about Boundry is a
#: governance question and this is only the tripwire that says one moved.
#: ⚠ **A TUPLE OF `name:digest` STRINGS, AND THE SHAPE IS THE WHOLE POINT.**
#: The first draft was a `dict[str, str]` — and `vocabulary_sweep.member_digest`
#: hashes a MAPPING'S KEYS ONLY (a count taken from a keyed structure
#: is a count of keys). Measured: change a value, the digest does not
#: move. **Registering it as a dict would have produced a row that could never
#: detect the change it exists to detect** — the defect delivered by the
#: instrument meant to prevent it. A flat tuple of strings is hashed whole.
# ⚠⚠ **THE DESCRIPTION IS ATTACHED HERE, NOT TYPED SEVEN TIMES.** `TOOL_SCHEMAS` above is a
# LITERAL, and it has to stay one: the shipped checks read it out of this file with
# `ast.literal_eval`, so that what they check is the source rather than whatever the import
# produced. A derived string cannot live inside a literal. Typing it into all seven would be the
# second copy forbids — and the copy that goes stale is always the one nothing derives.
#
# > ***DERIVE IT, AND THERE IS NOTHING TO KEEP IN STEP. ATTACH IT, AND THE LITERAL STAYS A
# > LITERAL.***
for _schema in TOOL_SCHEMAS:
    _schema["inputSchema"]["properties"]["corpus_dir"]["description"] = _CORPUS_DIR_DESCRIPTION


TOOL_DESCRIPTION_DIGESTS: tuple[str, ...] = tuple(sorted(
    f"{t['name']}:"
    f"{_hashlib.sha256(t.get('description', '').encode('utf-8')).hexdigest()}"
    for t in TOOL_SCHEMAS
))
