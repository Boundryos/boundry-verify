"""The chain over a bundle, to a verdict — STOP-C.

Implements section 12 of the verification-bundle specification, **RATIFIED and amended**,
block hash
`0100c67c103a32897cee587d2f6f7e5b98cad195a94a4247087deb8db92d5e86`, 39411
bytes — extending section 8 of the checkpoints-and-receipts specification. **Built from
those documents alone; the kernel repository has not been read.**

> **⚠ The era key comes from the KEY DIRECTORY and never from the bundle**
> (`BV-012`, `D5-f`). `directory` is a required keyword argument and there is no
> path by which a value from the bundle can reach a signature check as a key.

## ⚠ What changed — three clauses, and one of them was invisible

**Steps 2 and 5 verified a `COSE_Sign1`. `BV-025` says they must not.** A sealed
record's signature is raw Ed25519 over the payload's canonical bytes and a COSE
signature is over a `Sig_structure`, **so the existing signature is not a COSE
signature and re-labelling it would be a lie told in a field label.** The
container now carries the bytes as made and NAMES the construction; the
construction is resolved in `signature_form.py` and **an unrecognised name
stops verification.**

**Step 4 checked `CEF-001`'s key set and none of its field rules.** A leaf
recomputed from an envelope carrying uppercase hex or a negative `position` is a
hash of something that is not a canonical envelope, and the failure surfaced one
rung later under the wrong name.

**`BV-017` said EVERY downstream verdict and four of eleven carried it.** It is
in `_NEVER` now, where a verdict cannot be built without it. *That is the
invisible one: nothing failed, no test caught it, and every rung that did not
carry it was over-claiming by omission exactly as the clause says.*

## What changed from STOP-B

**`BV-006` reshaped (`H-7`).** `checkpoint.statement` is a MAP. The verifier
**re-emits** its canonical bytes and verifies the detached COSE_Sign1 over the
re-emission, then reads `head_construction_id`, `era`, `head_hash` and
`ledger_ordinal` **from the map, after the signature has verified.** Same check,
different route — and the route that leaves the fields readable (`BV-015`).
`canonical_read.py` is deleted.

**`D5-e` in full (STOP-C).** A ruling recorded STOP-B's result precisely: a forged
bundle returned `UNATTESTED` **because `witness_keys` was never read**, which is
*"the right answer for the wrong reason — correct by omission, and omission is
not a property."*

> **It is a property now.** `witness.py` holds a real trust list, the anchored
> path executes, and **`ATTESTED` is reachable** — so `UNATTESTED` on a forged
> bundle is an *outcome of anchoring* rather than an absence of code. The
> guarantee moved from *"this module does not read the field"* to
> **`verify_token` having no parameter through which a bundle-supplied key could
> arrive**, which survives the next person adding a branch here.
>
> The bundle's `witness_keys` IS read now — by `_bundle_witness_copy`, whose
> result reaches only `agreement_finding`, which returns a sentence.
> *(`BV-011`: a named finding, neither lowering nor raising the verdict.)*

## What an absent anchor produces, and why it is not a failure

`ERR-P3-008` separates *"no evidence"* from *"evidence that failed"*. An era the
directory does not carry, a witness the trust list does not anchor, and a
`witness_kind` this verifier cannot check (`H-8`) are all the first case:
**nothing could be evaluated.** They are `UNATTESTED`, under distinct reason
codes. `REFUTED` is reserved for a check that ran and did not pass.

**⚠ `BV-028` is the general form of that, and brings §12
step 3 to it: an unrecognised `head_construction_id` is now `UNATTESTED`.** *It
had been `REFUTED` from the start; a finding reported the disagreement with
the signature rung instead of harmonising it, and the ruling came back on the
side of the newer rung.* **⚠ THE ONE PLACE WHERE THE TWO CLAUSES COULD NOT BOTH BE OBEYED IS CLOSED.**
*A finding reported that the token-checker refusal branch returned `REFUTED`
for four causes `BV-028` calls `UNATTESTED`, while `BV-020`'s closed reason set
had no fact to report them under — so there was no conforming code to write, and
minting one would have been minting the specification.* **A ruling decided both
sides: `BV-020` gains a fifth fact, and a token checker returning one boolean
cannot be conformant with `BV-028`.** The witness refusal branch in
`_witness_rungs` is now a five-way dispatch on a closed result vocabulary, and
`REFUTED` there means only what `ERR-P3-008` reserves it for.
"""

from __future__ import annotations

import base64
import hashlib
import json

from .bundle import Bundle
from .canonical_form import CanonicalFormError, canonical_bytes
from .checkpoint import (CheckpointError, CheckpointStatement,
                         detect_equivocation, resolve_construction,
                         witness_message)
from .envelope_form import CEF_KEYS
from .envelope_form_v3 import (DISPATCH_KEY, CEF_V3_KEYS,
                               CEF_V3_OPTIONAL_KEYS, CEF_V3_VERSION)
from .keys import KeyDirectory, KeyDirectoryError
from .merkle import (MerkleError, leaf_hash, verify_consistency,
                     verify_inclusion)
from .envelope_form import FORBIDDEN_PREV_HASHES, GENESIS_SENTINEL, CEF_VERSION
from .receipt import Receipt, ReceiptError
from .signature_form import SignatureFormError
from .signature_form import resolve as resolve_signature_form
from .verdict import ALTERED, ATTESTED, REFUTED, UNATTESTED, Report, Verdict
from .witness import (NO_CHECKER, REFUSAL_CLASS_ABSENT,
                      TOKEN_REFUSED_CHECKER_SHORT, TOKEN_REFUSED_TOKEN_DEFECT,
                      TOKEN_VERIFIED, WitnessTrustList, agreement_finding,
                      verify_token)

__all__ = ["verify_bundle", "RECOGNISED_PAYLOAD_FORM_TAGS",
           "ENVELOPE_KEYS_BY_BUNDLE_VERSION",
           "ENVELOPE_OPTIONAL_KEYS_BY_BUNDLE_VERSION"]

#: `BV-005`: `form_tag` is *"which canonical form produced them"* — and `them`
#: is `record.canonical_bytes`, *"the payload's canonical bytes under"* the canonical form.
#:
#: ⚠ **SO THIS SET IS THE PAYLOAD'S CANONICAL FORMS, AND IT HELD THE ENVELOPE'S
#: FOR TWO PACKS**. As shipped it read
#: `{"v1", "v3"}` — `v3` being the canonical ENVELOPE form, which is governed by
#: a different specification and never belonged in a `form_tag`. **The ratified
#: reading governs**: the payload's canonical form is `v1` and there is no
#: other, so this set has exactly one member until the Phase 4 era boundary
#: mints a second.
#:
#: ⚠ **RENAMED, BECAUSE THE OLD NAME IS WHERE THE CONFUSION LIVED** —
#: enforced where it can refuse: every importer of `RECOGNISED_FORM_TAGS` now
#: fails at import rather than reading a set whose meaning changed under it).
#: The keyword argument keeps the specification's own word, `form_tag`.
#:
#: ⚠ **The no-default discipline
#: covers EVERY named profile identifier, `form_tag` included.** This set is
#: what this verifier implements; **it is never applied automatically.** A
#: caller must pass it, exactly as it must pass a witness trust list and a table
#: of token verifiers.
#:
#: > **Phase 4 is why this is not cosmetic.** *A verifier that defaults
#: > `form_tag` to `v1` will, at the era boundary, read `v2` bytes under `v1`
#: > rules and say nothing.* **Not provisioned and provisioned-with-v1 are
#: > different facts**, and only one of them means the operator has decided.
#:
#: ⚠ **Resolved at CALL time, never as a parameter default.** A default argument
#: is bound when the function is DEFINED, so a mutation of this name would never
#: reach the comparison and would read `INERT` — a knob that looks like
#: configuration and is a copy. That is `M12`'s defect and `verdict._OUTCOME_GUARDS`'
#: defect, and it is now three files. *A constant a test can change must be read
#: where it is used.*
RECOGNISED_PAYLOAD_FORM_TAGS = frozenset({"v1"})

#: §5's `envelope`, by the bundle version carrying it. `CEF-001`'s
#: five keys under version 1; the v3 form's eight under version 2.
ENVELOPE_KEYS_BY_BUNDLE_VERSION = {1: CEF_KEYS, 2: CEF_V3_KEYS}

#: ⚠ **v1 HAS NO OPTIONAL KEY.** `CEF-001`: *"no field is optional and none is
#: ever omitted"* — genesis is a sentinel VALUE there. v3 expresses genesis by
#: ABSENCE, so two keys may be missing and no others.
ENVELOPE_OPTIONAL_KEYS_BY_BUNDLE_VERSION = {1: frozenset(), 2: CEF_V3_OPTIONAL_KEYS}

# ⚠ **THE ENVELOPE FORM IS IDENTIFIED BY THE BUNDLE VERSION**,
# which fixes the key set below (`BV-033`). Nothing reads `form_tag` to identify
# it: *the envelope is self-describing — a v3 mapping carries
# `canonical_version` — and the tag names the payload's form.*

#: `BV-017`. A bundle holds one record's envelope; `CEF-007`'s property is about
#: the chain that envelope sits in, and a single envelope cannot witness it.
#:
#: ⚠ **`BV-017` says "the limit is carried in EVERY downstream verdict", and it
#: was carried in four of them** — the payload-binding pair, the inclusion rung
#: and the `ALTERED` path. **The encoding, statement, signature, construction
#: and witness rungs did not carry it.** Moved into `_NEVER`, so a
#: verdict cannot be constructed without it rather than being given it by a
#: caller who remembered. *A verifier that quietly omits what it could not check
#: is over-claiming by omission, and a rule enforced at each call site is
#: enforced until the next call site.*
_CEF007_NOT_ESTABLISHED = (
    "CEF-007's genesis biconditional: a bundle carries no genesis fact, and "
    "ERR-P3-001 forbids inferring one from the envelope form (BV-017)",
)

#: What no rung in this ladder ever establishes. `CP-010`, `BV-014`, `BV-017`.
_NEVER = (
    "that this record is current: a complete, attested bundle for a superseded "
    "record is still a bundle for a superseded record (BV-014, CP-010)",
    "that the content is correct, or that anyone was authorised to record it",
    "anything about records other than this one",
) + _CEF007_NOT_ESTABLISHED


def _verify_named_signature(report: Report, rung: str, holder: dict, message: bytes,
                            public_key: bytes,
                            recognised_signature_forms) -> bool:
    """`BV-025` / section 12 steps 2 and 5. Returns True only if it verified.

    **The construction is READ from the object and RESOLVED, never assumed.** An
    unrecognised `signature_form` **STOPS verification** — the specification says
    so twice, in section 12 step 2 and again in `BV-025`, and both times in those
    words.

    ## ⚠ Why an unresolvable form is `UNATTESTED` and not `REFUTED`

    `ERR-P3-008` draws the line at whether a check RAN. **`REFUTED` is reserved
    for evidence that was supplied and failed.** A form this verifier cannot
    resolve means **no check ran at all**: the bytes were never presented to any
    construction, so nothing about them was evaluated. *Treating "I could not
    check this" as "this did not check out" inverts the one distinction
    `ERR-P3-008` exists to preserve* — the same reasoning
    `witness-kind-not-implemented` already carries one rung down.

    > **⚠ THE ADJACENT RUNG USED TO DISAGREE, AND THE DISAGREEMENT IS NOW
    > RULED. KEPT, NOT DELETED.** Until `resolve_construction`'s
    > outcome at §12 step 3 was **`REFUTED`** on materially identical facts: a
    > named construction this verifier does not hold, and a check that therefore
    > never ran. **This rung was reported as disagreeing with that one
    > rather than harmonised on sight**, one of the fourteen runs
    > turned on the choice, and a ruling found **this** rung right, minted
    > `BV-028` from it and corrected §12 step 3. *Harmonising it
    > unasked would have produced the same code and destroyed the record that
    > there had been a disagreement.* **Nothing in this function changed.**
    """
    try:
        construction = resolve_signature_form(
            holder["signature_form"],
            recognised_signature_forms=recognised_signature_forms)
    except SignatureFormError as exc:
        report.add(_v(rung, UNATTESTED,
                      extra=("whether the signature would verify: no construction "
                             "was available to check it under, so the bytes were "
                             "never presented to one",),
                      detail=f"{exc.code}: {exc.detail}"))
        return False

    if not construction(public_key, message, holder["signature"]):
        report.add(_v(rung, REFUTED,
                      extra=("which of the possible causes applies: corrupted "
                             "bytes, the wrong era, and a signature that was never "
                             "over these bytes all produce this",),
                      detail=f"the signature does not verify over these bytes under "
                             f"{holder['signature_form']!r}, with the era key from "
                             "the directory"))
        return False
    return True


def _envelope_field_faults(envelope: dict, bundle_version: int) -> list[str]:
    """Section 12 step 4, routed by the version of the container carrying it.

    ⚠ **BOTH BRANCHES, NOT ONE** (*a fix applied to one branch of a
    type dispatch is a fix applied to one branch*). The v1 rules below are
    unchanged; `_envelope_field_faults_v3` states v3's, and the two are
    exercised by their own vectors.

    ⚠ **`bundle_version` HAS NO DEFAULT.** A default of `1` would read a v2
    envelope under v1's rules and report faults about keys it does not have —
    which is `BV-004`'s defect (*a verifier that invents an identifier and then
    recognises it has certified its own guess*) inside a helper.
    """
    if bundle_version == 2:
        return _envelope_field_faults_v3(envelope)
    return _envelope_field_faults_v1(envelope)


def _envelope_field_faults_v3(envelope: dict) -> list[str]:
    """v3's field rules, read from a bundle.

    ⚠ **AND ONE RULE BECOMES CHECKABLE HERE THAT IS NOT CHECKABLE FOR v1.**
    v1 states `CEF-007` over a SENTINEL VALUE and `ERR-P3-001` forbids inferring
    genesis from the envelope alone, so the biconditional cannot be applied from
    a bundle. **v3 states it over PRESENCE and POSITION — both of which are in
    the envelope** — so a v3 envelope whose `position` is 0 while carrying a
    predecessor, or whose position is positive while omitting one, is malformed
    on its face and is refused here.

    > ⚠ **THIS DOES NOT NARROW `BV-017`, AND THE DISTINCTION IS THE WHOLE
    > POINT.** What is checked is the FORM's internal consistency. That this
    > envelope really is its chain's genesis is a fact about the chain, which a
    > single envelope still cannot witness — so `_CEF007_NOT_ESTABLISHED` is
    > carried in every verdict here exactly as before. *A form rule that can be
    > checked and a chain fact that cannot are two different claims, and reading
    > the first as the second is over-claiming with the specification's own
    > vocabulary.*
    """
    faults = []
    version = envelope[DISPATCH_KEY]           # Named, not spelled
    if isinstance(version, bool) or not isinstance(version, int) \
            or version != CEF_V3_VERSION:
        faults.append(f"CEF-003: canonical_version is {version!r}; a "
                      f"bundle_version 2 container carries canonical form "
                      f"{CEF_V3_VERSION} and this verifier will not guess a field "
                      "set for another")
    if not isinstance(envelope["envelope_kind"], str) or not envelope["envelope_kind"]:
        faults.append("CEF-001: envelope_kind must be a non-empty text string")
    if not _is_sha256_hex(envelope["payload_hash"]):
        faults.append("CEF-001/CF-HASH-001: payload_hash must be 64 LOWERCASE hex "
                      "digits")
    position = envelope["position"]
    if isinstance(position, bool) or not isinstance(position, int):
        faults.append("CEF-001: position must be an integer")
    elif position < 0:
        faults.append("ERR-P3-002: position is zero-based and must not be negative")
    stamp = envelope["transition_timestamp_us"]
    if isinstance(stamp, bool) or not isinstance(stamp, int):
        faults.append("CEF-001: transition_timestamp_us must be an integer of "
                      "microseconds since the Unix epoch")
    elif stamp < 0:
        faults.append("CEF-001: transition_timestamp_us must not be negative")
    principal = envelope["submitter_principal_id"]
    if not isinstance(principal, str) or not principal:
        faults.append("CEF-V3-001: submitter_principal_id must be a non-empty "
                      "string -- a v3 envelope with no author is the "
                      "contradiction the version exists to prevent")
    if "submitter_domain_ref" in envelope:
        ref = envelope["submitter_domain_ref"]
        if not isinstance(ref, str) or not ref:
            faults.append("CEF-V3-001: submitter_domain_ref must be a non-empty "
                          "string when present; absence is expressed by OMITTING "
                          "the key, never by an empty one")
    if "prev_envelope_hash" in envelope:
        prev = envelope["prev_envelope_hash"]
        if not isinstance(prev, str):
            faults.append("CEF-004: prev_envelope_hash must be a text string")
        elif prev in FORBIDDEN_PREV_HASHES:
            faults.append(f"CEF-008: prev_envelope_hash is a prohibited digest "
                          f"({prev[:12]}...)")
        elif not _is_sha256_hex(prev):
            faults.append("CEF-004: prev_envelope_hash must be 64 lowercase hex "
                          "digits")
    if isinstance(position, int) and not isinstance(position, bool):
        absent = "prev_envelope_hash" not in envelope
        if (position == 0) != absent:
            faults.append(
                "CEF-007: v3 states genesis by ABSENCE -- position 0 omits "
                "prev_envelope_hash and every other position carries one. "
                f"position={position} with the key "
                f"{'absent' if absent else 'present'} is malformed on its face; "
                "omitting it at a positive position would detach the record "
                "from its chain while still hashing to a leaf that looks valid")
    return faults


def _envelope_field_faults_v1(envelope: dict) -> list[str]:
    """Section 12 step 4 — the
    FIELD RULES, not only `CEF-001`'s key set.

    **The key set was checked and the field rules were not.** A `payload_hash`
    in uppercase hex, a negative `position`, a `canonical_envelope_form_version`
    of `2`, or `CEF-008`'s prohibited sentinel all produced a leaf hash of
    something that is not a canonical envelope — and the failure then surfaced
    one rung later as *"the inclusion proof does not place this leaf"*, which
    names the wrong thing.

    > **⚠ WHAT IS DELIBERATELY NOT CHECKED HERE, AND IT IS `ERR-P3-001`.**
    > `envelope_form.envelope_canonical_form` requires `is_genesis` **from the
    > caller** — *"an implementation MUST NOT infer genesis from the envelope
    > form alone"* — and **a bundle carries no genesis fact** (`BV-017`). So the
    > two `CEF-007` branches are unreachable from here, by rule, and calling
    > that constructor would mean supplying a genesis claim this verifier does
    > not hold. **Every rule that does NOT need the sequence's own state is
    > applied; the one that does is declared, not guessed.**
    """
    faults = []
    version = envelope["canonical_envelope_form_version"]
    if isinstance(version, bool) or not isinstance(version, int) \
            or version != CEF_VERSION:
        faults.append(f"CEF-003: canonical_envelope_form_version is {version!r}; "
                      f"this verifier implements {CEF_VERSION} and will not guess a "
                      "field set for another")
    if not isinstance(envelope["envelope_kind"], str):
        faults.append("CEF-001: envelope_kind must be a text string")
    if not _is_sha256_hex(envelope["payload_hash"]):
        faults.append("CEF-001/CF-HASH-001: payload_hash must be 64 LOWERCASE hex "
                      "digits")
    position = envelope["position"]
    if isinstance(position, bool) or not isinstance(position, int):
        faults.append("CEF-001: position must be an integer")
    elif position < 0:
        faults.append("ERR-P3-002: position is zero-based and must not be negative")
    prev = envelope["prev_envelope_hash"]
    if not isinstance(prev, str):
        faults.append("CEF-004: prev_envelope_hash must be a text string")
    elif prev in FORBIDDEN_PREV_HASHES:
        faults.append(f"CEF-008: prev_envelope_hash is a prohibited digest "
                      f"({prev[:12]}...) -- it is exactly what a catastrophically "
                      "broken implementation produces, and it is refused rather "
                      "than hashed")
    elif prev != GENESIS_SENTINEL and not _is_sha256_hex(prev):
        faults.append("CEF-004: prev_envelope_hash must be 64 lowercase hex digits, "
                      "or CEF-006's genesis sentinel")
    return faults


def _is_sha256_hex(value) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _payload_binds(payload_digest: str, committed: object) -> bool:
    """Section 12 step 4, as an isolable predicate — and `BV-018`'s subject.

    **The payload is bound to the record by exactly this one rung.** The leaf is
    computed from the ENVELOPE, so the inclusion proof cannot see a payload
    substitution at all: with this check disabled, a payload changed and
    re-signed passes every other rung. *A five-rung chain reads as defence in
    depth; on this property it is one rung and four spectators.*

    Kept as a module-level function so a test can disable exactly this and show
    that (`ISOLABLE-CHECK RULE`). `BV-018` is normative because it was measured
    here rather than reasoned about.
    """
    return payload_digest == committed


#: `BV-013` as narrowed. **What the comparison could not reach**, said
#: out loud in every finding it produces. *JSON and deterministic CBOR do not
#: carry the same value space: byte strings, exact decimals and integer-width
#: distinctions do not all survive the crossing intact* — so `record`,
#: `inclusion_proof`, `receipts` and `witness_keys` are NOT COMPARED, and
#: `not compared` is never rendered as agreement.
_NOT_COMPARED = (
    "NOT COMPARED, and not thereby agreed: record, inclusion_proof, receipts and "
    "witness_keys. Their values do not all survive the crossing into JSON, and "
    "this specification defines no mapping for the ones that do not (BV-013 as "
    "narrowed at R-24)")


def _json_view_finding(body: dict) -> str | None:
    """`BV-013`. Parse the JSON view SOLELY to report disagreement with the CBOR,
    as a finding against the exporter. **It never contributes to a verdict** —
    this returns text, and the text reaches a `detail` field and nothing else.

    > **⚠ `BV-013` permits reporting disagreement, but the JSON
    > view's STRUCTURE is not specified anywhere**, and neither is the mapping
    > from CBOR to JSON — a CBOR byte string has no unambiguous JSON
    > counterpart. **So "disagreement" is only decidable where the values are
    > already JSON-representable.**
    >
    > This compares exactly one thing: `checkpoint.statement`, whose six
    > `CP-011` fields are integers and text strings and therefore survive the
    > crossing intact. **Everything else is reported as not compared, rather
    > than silently treated as agreeing** — *a comparison that quietly skips
    > what it cannot handle reports agreement it never established.*
    """
    if "json_view" not in body:
        return None
    try:
        view = json.loads(body["json_view"])
    except ValueError as exc:
        return f"json_view is not valid JSON ({exc}); finding against the exporter"
    if not isinstance(view, dict):
        return (f"json_view is a JSON {type(view).__name__}, not an object; "
                "finding against the exporter")
    shown = view.get("checkpoint", {})
    shown = shown.get("statement") if isinstance(shown, dict) else None
    if not isinstance(shown, dict):
        return ("json_view carries no checkpoint.statement object, so nothing "
                "in it could be compared. The view's structure is unspecified; "
                "this is not a claim that it agrees. "
                + _NOT_COMPARED)
    truth = body["checkpoint"]["statement"]
    differing = sorted(k for k in truth if shown.get(k) != truth[k])
    if differing:
        return (f"json_view's checkpoint.statement disagrees with the CBOR "
                f"on {differing}. FINDING AGAINST THE EXPORTER; the CBOR governs and "
                "the view contributed nothing to any verdict. " + _NOT_COMPARED)
    # ⚠ NOT `None`. `BV-013` as narrowed: the comparison is defined
    # ONLY over values that survive the crossing, and *"`not compared` is never
    # rendered as agreement."* Returning nothing here left a bundle whose view
    # matched on the six statement fields looking, to a reader, as though the
    # view had been checked -- which is the over-claiming-by-omission that
    # `BV-017` names one section along.
    return ("json_view's checkpoint.statement agrees with the CBOR on all "
            "six CP-011 fields. " + _NOT_COMPARED)


def _v(rung, outcome, *, established=(), extra=(), detail=""):
    return Verdict(rung, outcome, established=established,
                   not_established=_NEVER + tuple(extra), detail=detail)


def _bundle_witness_copy(body: dict, witness_key_ref: str):
    """The bundle's own copy of a witness key. **`BV-011` use only.**

    Its result reaches `agreement_finding` and nothing else. It is never passed
    to `verify_token`, which has no parameter that could accept it.
    """
    for entry in body["witness_keys"]:
        if entry.get("witness_key_ref") == witness_key_ref:
            return entry.get("key_material"), entry.get("format")
    return None, None


def verify_bundle(bundle: Bundle, *, directory: KeyDirectory,
                  witness_trust_list: WitnessTrustList | None = None,
                  token_verifiers: dict | None = None,
                  recognised_form_tags: frozenset[str] | None = None,
                  recognised_signature_forms: frozenset[str] | None = None,
                  key_reduction_limits=None) -> Report:
    """Section 12, in order. Returns a `Report`; never raises for evidence that
    fails, because a failed check is a verdict rather than an error.

    `witness_trust_list`, `token_verifiers`, `recognised_form_tags` and
    `recognised_signature_forms` are **provisioned inputs with no defaults in
    substance**: `None` means *this verifier was never provisioned*, which is a
    different fact from an empty trust list (*anchors nobody*) and produces a
    different reason code.

    *`recognised_form_tags` joined them first. Until then it fell
    back to `RECOGNISED_FORM_TAGS`, which is a default wearing a constant's
    clothes.* **`recognised_signature_forms` joins them, by the
    same rule: `BV-004` as extended covers EVERY named profile identifier in a
    bundle, and `BV-025` added one.**

    **`key_reduction_limits` joins them.** `BV-011` as corrected
    compares the KEYS two representations denote, and reducing a certificate to
    its key is a **parse of bundle-supplied bytes** — so it takes a bound, and
    `BV-023` gives bounds no default. **`None` means this verifier was not
    provisioned to parse a key representation**, which makes any comparison
    needing one `NOT COMPARED` rather than a difference (`BV-028`).
    """
    report = Report()
    body = bundle.body
    record = body["record"]
    # --- step 1 (already done by bundle.parse) ---------------------------
    report.add(_v("bundle encoding", ATTESTED,
                  established=(f"the bundle decodes, round-trips and declares "
                               f"{bundle.encoding_id!r}, which this verifier was "
                               "provisioned to recognise",),
                  extra=("anything about the contents: a bundle is a "
                         "container and an UNSIGNED one",),
                  detail="; ".join(
                      bundle.notes + [f for f in (_json_view_finding(body),) if f])
                      or "no optional fields present"))

    # --- step 2: re-emit the statement, verify over the RE-EMISSION ------
    try:
        statement = CheckpointStatement(body["checkpoint"]["statement"])
        statement_bytes = statement.canonical_bytes()
    except (CheckpointError, CanonicalFormError, TypeError) as exc:
        # Named exactly. A blanket `except Exception` in a verifier turns its own
        # bugs into verdicts about someone else's record.
        report.add(_v("checkpoint statement", REFUTED,
                      extra=("anything downstream: without a statement there is no "
                             "head to prove inclusion against",),
                      detail=f"the checkpoint statement is not CP-011's closed "
                             f"six-key form, or does not canonicalise ({exc})"))
        return report
    report.add(_v("checkpoint statement", ATTESTED,
                  established=("the statement is CP-011's closed six-key form and "
                               "re-emits to canonical bytes (BV-015)",),
                  extra=("that the statement is genuine -- that is the next rung",)))

    try:
        era_key = directory.resolve(statement.era)
    except KeyDirectoryError as exc:
        report.add(_v("checkpoint signature", UNATTESTED,
                      extra=("whether the signature would verify: no key for this "
                             "era was available to check it with",),
                      detail=f"the era key is not resolvable from the provisioned "
                             f"directory ({exc}); a key may not be taken from "
                             "the bundle, so this rung is not reached rather than "
                             "guessed"))
        return report

    if not _verify_named_signature(
            report, "checkpoint signature", body["checkpoint"], statement_bytes,
            era_key.public_key, recognised_signature_forms):
        return report
    report.add(_v("checkpoint signature", ATTESTED,
                  established=(f"the checkpoint statement is signed under era "
                               f"{statement.era!r}, whose key came from the key "
                               "directory and not from the bundle",
                               f"the signature was checked under the construction "
                               f"{body['checkpoint']['signature_form']!r}, which the "
                               "container names beside it and this verifier was "
                               "provisioned to accept (BV-025)"),
                  extra=("that the head was seen by anyone other than the "
                         "operator -- that is the receipt rung (CP-002)",)))

    # --- step 3: the construction is READ from the verified map ----------
    try:
        construction = resolve_construction(statement)
    except CheckpointError as exc:
        # ⚠ **`UNATTESTED`, NOT `REFUTED` — corrected on
        # `BV-028`, and the outcome this rung gave was wrong.**
        #
        # `resolve_construction` raises here for exactly one cause: a
        # `head_construction_id` this verifier does not hold. **The check never
        # ran.** Nothing was presented to any construction, so nothing whatever
        # was learned about the record — and *a verifier that reports its own
        # incompleteness as `REFUTED` converts a gap in itself into evidence
        # against its subject.*
        #
        # A finding reported this rung and `_verify_named_signature`
        # disagreeing on materially identical facts and did not harmonise them;
        # The signature rung was ruled right, `BV-028` was minted from it, and
        # brought §12 step 3 to it. **The two rungs now agree, by a ruling
        # rather than by an implementer's tidying.**
        report.add(_v("head construction", UNATTESTED,
                      extra=("anything about inclusion: this verifier stops rather "
                             "than falling back to a construction it happens to "
                             "implement",
                             "whether the head would verify under the construction "
                             "the statement names: this verifier does not hold it, "
                             "so no check ran"),
                      detail=str(exc)))
        return report
    report.add(_v("head construction", ATTESTED,
                  established=(f"the statement names {statement.head_construction_id!r}, "
                               "which this verifier implements, read from the map "
                               "AFTER its signature verified",),
                  extra=("that any other construction would give the same head",),
                  detail=construction.get("note", "")))

    # --- step 4: the leaf, and the payload's binding to it ---------------
    envelope = record["envelope"]
    bundle_version = bundle.body["bundle_version"]
    allowed = ENVELOPE_KEYS_BY_BUNDLE_VERSION[bundle_version]
    optional = ENVELOPE_OPTIONAL_KEYS_BY_BUNDLE_VERSION[bundle_version]
    missing = [k for k in allowed if k not in envelope and k not in optional]
    extra_keys = [k for k in envelope if k not in allowed]
    if missing or extra_keys:
        report.add(_v("record envelope", REFUTED,
                      extra=("anything downstream",),
                      detail=f"the envelope's field set is closed for "
                             f"bundle_version {bundle_version}; "
                             f"missing={missing} unexpected={extra_keys}"))
        return report

    malformed = _envelope_field_faults(envelope, bundle_version)
    if malformed:
        report.add(_v("record envelope", REFUTED,
                      extra=("anything downstream: a leaf recomputed from an "
                             "envelope that is not in the canonical envelope form "
                             "is a hash of something, and of nothing named",),
                      detail="; ".join(malformed)))
        return report

    if recognised_form_tags is None:
        report.add(_v("record canonical form", UNATTESTED,
                      extra=("whether the bytes are well-formed under ANY canonical "
                             "form: without a provisioned set there is nothing to "
                             "read form_tag against",),
                      detail="form-tags-not-provisioned: this verifier was not told "
                             "which canonical forms it implements, so it cannot "
                             "interpret canonical_bytes. Stopping rather than "
                             "assuming v1"))
        return report

    if record["form_tag"] not in recognised_form_tags:
        report.add(_v("record canonical form", REFUTED,
                      extra=("whether the bytes are well-formed under some other "
                             "canonical form",),
                      detail=f"form_tag {record['form_tag']!r} is not one this "
                             f"verifier implements; stopping rather than assuming "
                             "a form"))
        return report

    payload_digest = hashlib.sha256(record["canonical_bytes"]).hexdigest()
    if not _payload_binds(payload_digest, envelope.get("payload_hash")):
        report.add(_v("record payload binding", ALTERED,
                      extra=("when the difference arose",),
                      detail="the payload's canonical bytes do not hash to the "
                             "payload_hash the envelope commits to (no "
                             "other rung would have noticed)"))
        return report
    report.add(_v("record payload binding", ATTESTED,
                  established=("the payload's canonical bytes hash to the "
                               "payload_hash carried in the envelope",)))

    # --- step 5: the record's own signature -----------------------------
    if not _verify_named_signature(
            report, "record signature", record, record["canonical_bytes"],
            era_key.public_key, recognised_signature_forms):
        return report
    report.add(_v("record signature", ATTESTED,
                  established=("the payload's canonical bytes are signed under era "
                               f"{statement.era!r}",
                               f"the signature was checked under "
                               f"{record['signature_form']!r} -- the construction it "
                               "was MADE under, named beside it, not one this "
                               "verifier assumed (BV-025)"),
                  extra=("that the operator was authorised to record it (BV-014)",)))

    # --- step 6: inclusion, tree_size DERIVED from ledger_ordinal --------
    try:
        verify_inclusion(
            leaf_hash(canonical_bytes(envelope)),
            record["leaf_index"],
            statement.ledger_ordinal,          # BV-008: derived, never carried
            list(body["inclusion_proof"]["path"]),
            bytes.fromhex(statement.head_hash),
        )
    except (MerkleError, ValueError) as exc:
        report.add(_v("inclusion", REFUTED,
                      detail=f"the inclusion proof does not place this leaf under "
                             f"the signed head ({exc})"))
        return report
    report.add(_v("inclusion", ATTESTED,
                  established=(f"leaf {record['leaf_index']} is under the head the "
                               f"checkpoint signs, with tree_size derived from "
                               f"ledger_ordinal ({statement.ledger_ordinal}) rather "
                               "than carried (BV-008)",)))

    # --- step 7: receipts, D5-e in full ---------------------------------
    _witness_rungs(report, body, statement, witness_trust_list,
                   token_verifiers or {}, key_reduction_limits)

    # --- step 8: consistency, where a prior checkpoint is present --------
    if "prior_checkpoint" in body:
        _consistency(report, body, statement, directory,
                     recognised_signature_forms)

    return report


_ANCHOR_NEVER = (
    "that the witness is a party independent of the operator: an operator who "
    "runs their own witness, and whom this verifier has anchored, passes "
    "(ERR-CP-001)",
    "that the anchored key is the one the witness actually uses today: an "
    "anchor is a provisioning decision, not a live lookup",
)


def _witness_rungs(report: Report, body: dict, statement: CheckpointStatement,
                   trust: WitnessTrustList | None, token_verifiers: dict,
                   key_reduction_limits=None) -> None:
    receipts = body["receipts"]
    if not receipts:
        report.add(_v("witness receipt", UNATTESTED,
                      extra=("when this head was seen by any party other than the "
                             "operator; order and time rest on the operator alone",),
                      detail="witness-no-receipt: no receipt is present. This is not "
                             "a finding against the record (CP-008)"))
        return

    attested = witness_message(statement)          # ERR-P3-004 / ERR-P3-007
    for i, raw in enumerate(receipts):
        rung = f"witness receipt[{i}]"
        try:
            parsed = Receipt(raw)
        except ReceiptError as exc:
            report.add(_v(rung, REFUTED, extra=("anything about the witness",),
                          detail=f"the receipt is not well-formed ({exc})"))
            continue
        if not parsed.attests_to(statement):
            report.add(_v(rung, REFUTED,
                          extra=("whether the receipt attests to some other "
                                 "checkpoint, which it may well do",),
                          detail="the receipt attests to a digest "
                                 "other than this checkpoint statement's"))
            continue

        if trust is None:
            report.add(_v(rung, UNATTESTED, extra=_ANCHOR_NEVER,
                          detail="witness-no-trust-list: this verifier was not "
                                 "provisioned with a witness trust list, so no "
                                 "witness can be anchored: the bundle's own "
                                 "witness_keys can never supply that anchor"))
            continue

        anchor = trust.anchor_for(parsed.witness_key_ref)
        if anchor is None:
            report.add(_v(rung, UNATTESTED, extra=_ANCHOR_NEVER,
                          detail=f"witness-not-anchored: this verifier does not "
                                 f"anchor {parsed.witness_key_ref!r}. The bundle "
                                 "carries key material for it and that material "
                                 "confers nothing; a bundle that vouches "
                                 "for itself has vouched for nothing"))
            continue

        # BV-011. The bundle's copy is read HERE and nowhere else, and all it
        # can produce is a sentence.
        finding = agreement_finding(
            anchor, *_bundle_witness_copy(body, parsed.witness_key_ref),
            limits=key_reduction_limits)

        result, reason = verify_token(
            anchor, witness_kind=parsed.witness_kind,
            token=base64.b64decode(parsed.witness_token),
            attested_digest=attested, token_verifiers=token_verifiers)

        suffix = f" · FINDING: {finding}" if finding else ""
        if result == TOKEN_VERIFIED:
            report.add(_v(rung, ATTESTED,
                          established=(f"the receipt attests to this checkpoint's "
                                       "digest",
                                       f"its token verifies under the ANCHORED key "
                                       f"for {anchor.witness_key_ref!r}, taken from "
                                       "the provisioned trust list and never from "
                                       "the bundle"),
                          extra=_ANCHOR_NEVER, detail=reason + suffix))
        elif result == NO_CHECKER:
            # H-8, and `BV-020`'s THIRD fact. `ERR-P3-005` makes the token the
            # witness's own artefact. Absence of a checker is absence of
            # evidence, never evidence of failure -- treating "I could not check
            # this" as "this checks out" inverts the one distinction
            # `ERR-P3-008` exists to preserve.
            report.add(_v(rung, UNATTESTED, extra=_ANCHOR_NEVER,
                          detail=f"witness-kind-not-implemented: {parsed.witness_kind!r} "
                                 "is anchored, and its token is opaque to this "
                                 "verifier by design. Checking it means "
                                 "implementing that witness's own format, which no "
                                 "checker was provisioned for"
                                 + suffix))
        elif result == TOKEN_REFUSED_CHECKER_SHORT:
            # ⚠ `BV-020`'s FIFTH FACT, ruled and
            # implemented here. **THIS BRANCH RETURNED `REFUTED` UNTIL
            #
            # The witness IS anchored, a checker for its kind DOES exist, IT
            # RAN, and it holds no implementation for something the token or the
            # anchor declares. *`BV-028`: the check never ran, so nothing
            # whatever was learned about the record, and a verifier that reports
            # its own incompleteness as `REFUTED` converts a gap in itself into
            # evidence against its subject.*
            #
            # ***The operator has climbed every step of the staircase — they
            # anchored the witness, they provisioned the checker — and they
            # still get nothing. A verdict that cannot say so sends them to
            # solve the wrong problem.***
            report.add(_v(rung, UNATTESTED, extra=_ANCHOR_NEVER + (
                              "anything about the token: this build could not "
                              "evaluate what it declares, so the token has been "
                              "neither confirmed nor impugned",),
                          detail=reason + suffix))
        elif result == REFUSAL_CLASS_ABSENT:
            # ⚠ `BV-020`'s SELF-REPAIRING clause, and this is the branch it was
            # minted for: *a verifier that finds itself lacking something no
            # fact names MUST REPORT THAT AS A SPECIFICATION FINDING AND MUST
            # NOT ABSORB IT INTO `REFUTED`.*
            #
            # A provisioned checker refused without declaring its class, so this
            # verifier cannot tell "the token is wrong" from "we are short" --
            # and `BV-028` forbids guessing. **The finding is against the
            # CHECKER's contract, not against the record.**
            report.add(_v(rung, UNATTESTED, extra=_ANCHOR_NEVER + (
                              "which class of refusal the checker meant, which "
                              "is the checker's to say and was not said",),
                          detail=reason + suffix))
        elif result == TOKEN_REFUSED_TOKEN_DEFECT:
            # Evidence supplied, and it failed.
            #
            # ⚠ `reason`, not a literal. Until STOP-B this branch
            # authored its own sentence and DISCARDED the reason, so a checker's
            # findings reached a reader on the ATTESTED path and were silently
            # dropped on the REFUTED one -- the path where a reader most needs
            # to know WHICH check failed.
            #
            # *`bundle_chain` cannot narrate the outcome of a checker it has
            # never seen: `BV-019` makes every checker provisioned, so the only
            # party that can say why one refused is the checker.* Corrects the
            # earlier analysis, which said `witness.py` was the only
            # file this needed -- true of the success path, and measurably not
            # of this one.
            #
            # ⚠⚠ **THE FINDING IS CLOSED HERE.** This branch used to catch every
            # refusal, including the four the checker raises when it is SHORT,
            # and report them all as `REFUTED` in direct violation of `BV-028`.
            # The ruling: `BV-020` gains a fifth fact, and a token checker
            # returning one boolean cannot be conformant. **The dispatch above
            # is that ruling, and this branch now catches only what
            # `ERR-P3-008` reserves `REFUTED` for.**
            report.add(_v(rung, REFUTED,
                          extra=_ANCHOR_NEVER + (
                              "which of the possible causes applies, beyond what "
                              "the checker itself reported",),
                          detail=reason + suffix))
        else:                                            # pragma: no cover
            # ⚠ UNREACHABLE BY CONSTRUCTION -- `witness._classify` admits only
            # `RESULTS` -- and it is here so that WIDENING that vocabulary fails
            # LOUDLY instead of falling into `REFUTED`. *`BV-020`'s
            # self-repairing clause, in code: a closed set a conforming
            # implementation cannot satisfy will be violated silently, and the
            # violation will look like a verdict.* **A dispatch whose default
            # arm is a verdict has a default verdict.**
            raise ValueError(
                f"verify_token returned {result!r}, which is not in "
                "witness.RESULTS; refusing to guess a verdict for it")


def _consistency(report: Report, body: dict, statement: CheckpointStatement,
                 directory: KeyDirectory, recognised_signature_forms) -> None:
    try:
        prior = CheckpointStatement(body["prior_checkpoint"]["statement"])
        prior_bytes = prior.canonical_bytes()
    except (CheckpointError, CanonicalFormError, TypeError) as exc:
        report.add(_v("consistency", REFUTED,
                      extra=("whether the ledger is append-only across this pair",),
                      detail=f"the prior checkpoint statement is not CP-011's "
                             f"closed six-key form ({exc})"))
        return

    # CP-017. Two statements in one era and construction at the same ordinal
    # with different heads are EVIDENCE OF EQUIVOCATION, and a holder of both
    # needs nothing from the operator to say so.
    equivocation = detect_equivocation(prior, statement)
    if equivocation:
        report.add(_v("consistency", REFUTED,
                      extra=("which of the two heads, if either, is the one the "
                             "ledger actually held",),
                      detail=equivocation))
        return

    try:
        prior_key = directory.resolve(prior.era)
    except KeyDirectoryError as exc:
        report.add(_v("consistency", UNATTESTED,
                      extra=("whether the earlier head is a prefix of this one",),
                      detail=f"the prior checkpoint could not be evaluated ({exc})"))
        return
    try:
        prior_construction = resolve_signature_form(
            body["prior_checkpoint"]["signature_form"],
            recognised_signature_forms=recognised_signature_forms)
    except SignatureFormError as exc:
        report.add(_v("consistency", UNATTESTED,
                      extra=("whether the earlier head is a prefix of this one",),
                      detail=f"{exc.code}: {exc.detail}"))
        return
    if not prior_construction(prior_key.public_key, prior_bytes,
                              body["prior_checkpoint"]["signature"]):
        report.add(_v("consistency", REFUTED,
                      extra=("whether the earlier head is a prefix of this one",),
                      detail="the prior checkpoint signature does not verify over "
                             "its re-emitted canonical bytes, under the era key "
                             "from the directory"))
        return

    if "consistency_proof" not in body:
        report.add(_v("consistency", UNATTESTED,
                      extra=("that nothing beneath the earlier head was changed or "
                             "removed",),
                      detail="a prior checkpoint is present with no consistency "
                             "proof to connect it; the pair is carried, not shown"))
        return

    try:
        verify_consistency(prior.ledger_ordinal, statement.ledger_ordinal,
                           bytes.fromhex(prior.head_hash),
                           bytes.fromhex(statement.head_hash),
                           list(body["consistency_proof"]["path"]))
    except (MerkleError, ValueError) as exc:
        report.add(_v("consistency", REFUTED,
                      extra=("which entries differ, or when they came to",),
                      detail=f"the earlier head is not shown to be a prefix of the "
                             f"later one ({exc})"))
        return
    report.add(_v("consistency", ATTESTED,
                  established=(f"the head at ledger_ordinal {prior.ledger_ordinal} "
                               f"is a prefix of the head at "
                               f"{statement.ledger_ordinal}: nothing beneath the "
                               "earlier head was changed or removed",),
                  extra=("anything about entries added after the later head",)))
