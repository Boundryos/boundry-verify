"""Bundle parsing — STOP-B, rebuilt.

**Built from the specification alone.** The kernel repository has not been read
and this consumer has not seen the exporter, which its governing order makes
the acceptance criterion rather than the hygiene.

> **⚠ THE SPECIFICATION VERSION THIS MODULE IMPLEMENTS IS NAMED, NOT ASSUMED.**
> The verification-bundle specification, block hash
> `86d6c4c54ea9a7e9a3719499ab70d4b75b0441fe7da50777f4e088dc5cea34c2`,
> **51769 bytes**, *`BV-001`…`BV-029`* — **RE-DERIVED.**
>
> **The pin this replaced named 39411 bytes, `0100c67c…`, `BV-001`…`BV-027`,
> and CARRIED ITS OWN STALENESS AS TEXT**: *"was true when
> written; the file was not re-derived when the document was amended."*
> **⚠ It then went stale a second time, by 12358 bytes and two clauses, and the
> sentence admitting the first drift did nothing to catch the second.**
>
> ***A MODULE THAT DOCUMENTS ITS OWN DRIFT AND KEEPS THE TEXT IS WORSE THAN ONE
> THAT SAYS NOTHING*** — the admission reads as diligence and
> discharges nobody. Re-derived rather than deleted, because the pin is worth
> having; what was not worth having was the apology attached to it.

## What changed, from findings this module produced

**`BV-006` reshaped (`H-7`): `checkpoint.statement` is a MAP, not bytes.** The
canonical form is an EMISSION form and is not injective, so *"read
`head_construction_id` out of the verified statement"* asked for an inverse that
does not exist. **`BV-015` generalises it — READ-OR-HASH: an object whose fields
a verifier must READ is carried as a map and re-emitted; an object it only
HASHES is carried as bytes.** `canonical_read.py`, written to work around the
old shape, is deleted.

**`BV-008` narrowed (`H-6`): restatement is prohibited in the container OUTSIDE
any commitment.** A value inside an object that is itself committed — by
signature, or by inclusion proof to a signed head — is not a restatement. **So
the restatement check runs at the container level and does NOT descend into
`record.envelope`, `checkpoint.statement`, or a receipt.** Read literally, the
old rule forbade `record.envelope.payload_hash`, which `CEF-001` requires.

## What changed from STOP-A, and why the file was rewritten rather than patched

STOP-A read the bundle as a **map** with a `bundle_encoding_id` key, because
that is what the order described. **`H-2` reported that such a key
cannot be positionally first under deterministic CBOR**, and `BV-002` answers it
by changing the shape: **the bundle is a two-item array `[encoding_id, body]`**,
so item 0 is first by construction and a reader cannot reach the body without
passing it.

*This is a different format, not a refinement of the old one*, so the old
parse path is gone rather than kept as a fallback — **a reader that accepts
both accepts two formats**, which is `BV-006`'s defect in the shape instead of
in the name.

## ⚠ What changed, and it is a VERSION SKEW rather than a reading

**This module implemented the bundle specification as it stood before
it was amended.** `RECORD_KEYS` carried `cose_sign1`; `CHECKPOINT_KEYS` carried
`cose_sign1`; **neither carried `signature` or `signature_form`, which
`BV-025` made required on both.** Every bundle exported under the current
document was refused at `bundle-unknown-key`, which is the correct refusal for
a field set this module did not have.

**Three further rows of `BV-005`'s table were enforced nowhere.** Map keys were
checked as text only on the maps `_check_map` walks by name; NFC text and the
tag restriction were not checked at all. **They are properties of the ENCODING
PROFILE**, so they moved to `cbor.BUNDLE` where the profile is read, rather than
being added as a fourth place that has to remember.

**And `BV-023` had no bundle-level implementation at all** — it existed only on
the DER path, so the one clause that governs the decode itself did not govern
the bundle's decode. `parse` now requires a bound and refuses beyond it; `read`
refuses *unread*, which is what the clause asks for.

## No verdicts here

This module parses and refuses. **It reaches no verdict** — the chain and its
verdicts are `bundle_chain.py`. Keeping them apart is what let STOP-A's
"no verdict vocabulary" test stay meaningful into STOP-B.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import os

from .cbor import BUNDLE as BUNDLE_PROFILE
from .cbor import CborError, Tag, assert_round_trip
from .cose import COSE_SIGN1_TAG

__all__ = ["BundleError", "Bundle", "BUNDLE_VERSION", "THIS_VERSION_ENCODING_ID",
           "BUNDLE_VERSION_V2", "BUNDLE_V2_ENCODING_ID",
           "RECOGNISED_BUNDLE_VERSIONS", "ENCODING_ID_BY_BUNDLE_VERSION",
           "BODY_REQUIRED", "BODY_OPTIONAL", "RESTATED_VALUE_KEYS",
           "RECORD_KEYS", "CHECKPOINT_KEYS", "PROOF_KEYS", "WITNESS_KEY_KEYS",
           "read", "parse", "REFUSALS"]

#: `BV-007`: `1` for the form ratified 30 Aug 2026.
BUNDLE_VERSION = 1

#: `BV-007`: the version whose `record.envelope` is the v3
#: canonical form — the sealed author. **The body's own key set is the same in
#: both;** what a version numbers here is the closed sub-map of §5.
BUNDLE_VERSION_V2 = 2

#: ⚠ **BOTH, AND THE OLD ONE IS NEVER DROPPED**. *Every
#: `bundle_version: 1` bundle stays verifiable forever* — a verifier that
#: retired a version would turn evidence somebody already holds into bytes
#: nobody can read, which is the one thing an offline verifier exists to
#: prevent. `INTEROP/` is frozen and its bundles stay exactly what they are.
RECOGNISED_BUNDLE_VERSIONS = frozenset({BUNDLE_VERSION, BUNDLE_VERSION_V2})

#: `BV-005`'s identifier. ⚠ **This is NOT a default.** `BV-004` makes the
#: recognised set a provisioned verifier input with no default, so this constant
#: exists to be *provisioned* by a caller that has decided to accept this
#: profile — never to be silently assumed by `parse`. The `cf1` suffix is
#: load-bearing (`BV-006`): the profile is RFC 8949 section 4.2.1 NARROWED by
#: the canonical-form specification, and an implementation that read only the
#: RFC would accept floats and diverge silently.
THIS_VERSION_ENCODING_ID = "bundle-cbor-det-cf1"

#: `bundle_version: 2`'s identifier. ⚠ **Also not a default** — `BV-004` has no
#: exception for a second version, and a verifier that recognised this one
#: because it had heard of it would be certifying its own guess in a newer
#: place. It is provisioned or it is refused.
#:
#: ⚠ **`cf1` STILL NAMES THE CANONICAL-FORM SPECIFICATION, WHICH HAS NOT
#: MOVED.** The CBOR narrowing is the same table; the `-v2` is the BUNDLE's
#: version. `BV-006` says an identifier that can be read two ways is
#: under-named, and *canonical form 2* is the other reading.
BUNDLE_V2_ENCODING_ID = "bundle-cbor-det-cf1-v2"

#: ⚠ **ONE VERSION, ONE IDENTIFIER.** `BV-003` step 3 reads item 0 and step 4
#: reads the body; a bundle naming one form in each has told a reader two
#: things, and only one of them is checked by the step that reads it.
ENCODING_ID_BY_BUNDLE_VERSION = {
    BUNDLE_VERSION: THIS_VERSION_ENCODING_ID,
    BUNDLE_VERSION_V2: BUNDLE_V2_ENCODING_ID,
}

#: `BV-007`. The set is CLOSED; an unknown key is a refusal.
BODY_REQUIRED = ("bundle_version", "record", "checkpoint", "inclusion_proof",
                 "receipts", "witness_keys")
BODY_OPTIONAL = ("key_directory_hint", "json_view", "prior_checkpoint",
                 "consistency_proof")

#: `BV-008`, NO-RESTATEMENT, **as narrowed**. Each of these is inside a
#: COMMITTED object, so an uncommitted copy in the container is *"a second place
#: to put a different one"*. Named separately from the closed-set check so the
#: refusal says WHY rather than merely "unknown key" — the two are different
#: findings against an exporter, and only one of them is a design error.
#:
#: ⚠ **Checked at the container level ONLY.** `checkpoint.statement` legitimately
#: carries all five of these names: it is committed by its own signature, so
#: they are the same commitment one level in, not a restatement. Descending into
#: it would refuse a conforming bundle — which is `H-6` in reverse, and is why
#: `_check_map` is called with `restatement=False` there.
RESTATED_VALUE_KEYS = ("era", "head_construction_id", "head_hash",
                       "ledger_ordinal", "tree_size")

#: Section 5's table, in full. `leaf_index` is carried because it is derivable
#: from nothing signed — `BV-008`'s test is derivability, not tidiness.
#:
#: ⚠ **`signature` and `signature_form` replace `cose_sign1`, at `BV-025`.** A
#: sealed record's signature is raw Ed25519 over the payload's canonical bytes;
#: a COSE_Sign1 signature is over a `Sig_structure` and never over the payload
#: alone, so **an existing signature is not a COSE signature and cannot be
#: re-labelled as one.** The container carries the bytes that were actually
#: produced and NAMES the construction beside them.
RECORD_KEYS = ("canonical_bytes", "envelope", "form_tag", "leaf_index",
               "signature", "signature_form")

#: Section 6's table. `statement` is the CP-011 six-key mapping as TYPED
#: VALUES; the verifier re-emits its canonical bytes and verifies `signature`
#: over the re-emission, under the construction `signature_form` names
#: (`BV-015`, `BV-025`).
CHECKPOINT_KEYS = ("signature", "signature_form", "statement")

#: `BV-007` section 7. `tree_size` is absent by `BV-008`; `leaf_index` lives in
#: `record` because it is a property of the record, not of the proof.
PROOF_KEYS = ("path",)

#: `BV-009`.
WITNESS_KEY_KEYS = ("witness_key_ref", "key_material", "format")

REFUSALS = (
    "bundle-not-deterministic",
    "bundle-is-signed",
    "bundle-not-an-array",
    "bundle-wrong-arity",
    "bundle-encoding-id-not-text",
    "bundle-encoding-unrecognised",
    "bundle-body-not-a-map",
    "bundle-key-not-text",
    "bundle-restated-value",
    "bundle-unknown-key",
    "bundle-missing-key",
    "bundle-field-type",
    "bundle-version-unknown",
    # --- one version, one identifier ---------------------
    "bundle-encoding-version-mismatch",
    # --- BV-023 --------------------------------------
    "bundle-size-bound-not-provisioned",
    "bundle-too-large",
)


class BundleError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass
class Bundle:
    encoding_id: str
    body: dict
    notes: list[str] = field(default_factory=list)


def _check_map(value, where: str, required, optional=(), *, restatement=True) -> dict:
    """Check one closed map: text keys, no restated value, no unknown, none missing.

    **The restatement check runs BEFORE the unknown-key check**, so a body
    carrying `tree_size` is refused as `bundle-restated-value` and not as a
    generic unknown key. The specification is explicit that such a bundle is *"a
    refusal, not a tolerated redundancy"*, and a refusal that does not say which
    kind of mistake it found has thrown away the reason it was worth naming.
    """
    if not isinstance(value, dict):
        raise BundleError("bundle-body-not-a-map",
                          f"{where} is {type(value).__name__}, not a map")
    for key in value:
        if not isinstance(key, str):
            raise BundleError("bundle-key-not-text",
                              f"{where}: map key {key!r} is {type(key).__name__}; "
                              "this profile carries named fields")
    for key in value if restatement else ():
        if key in RESTATED_VALUE_KEYS:
            raise BundleError(
                "bundle-restated-value",
                f"{where}.{key} is forbidden: it is determined by a "
                "signed object inside the bundle, and an unsigned second copy is "
                "a second place to put a different one. Derive it, never carry it")
    allowed = set(required) | set(optional)
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise BundleError("bundle-unknown-key",
                          f"{where}: unknown key(s) {unknown}; this key set is closed")
    missing = [key for key in required if key not in value]
    if missing:
        raise BundleError("bundle-missing-key", f"{where}: missing {missing}")
    return value


def _bstr(value, where: str) -> bytes:
    if not isinstance(value, bytes):
        raise BundleError("bundle-field-type",
                          f"{where} is {type(value).__name__}, not a byte string")
    return value


def _text(value, where: str) -> str:
    if not isinstance(value, str):
        raise BundleError("bundle-field-type",
                          f"{where} is {type(value).__name__}, not a text string")
    return value


def _uint(value, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BundleError("bundle-field-type", f"{where} must be an unsigned integer")
    return value


def _check_proof(value, where: str) -> None:
    _check_map(value, where, PROOF_KEYS)
    path = value["path"]
    if not isinstance(path, list):
        raise BundleError("bundle-field-type",
                          f"{where}.path is {type(path).__name__}, not an array")
    for i, element in enumerate(path):
        _bstr(element, f"{where}.path[{i}]")


def _check_checkpoint(value, where: str) -> None:
    _check_map(value, where, CHECKPOINT_KEYS)
    statement = value["statement"]
    if not isinstance(statement, dict):
        raise BundleError("bundle-field-type",
                          f"{where}.statement is {type(statement).__name__}, not a "
                          "map. The statement is carried as typed values so its "
                          "fields can be READ")
    # BV-008 as narrowed: the statement is committed by its own signature, so
    # `era`, `head_hash`, `ledger_ordinal` and `head_construction_id` belong
    # here. CP-011's field set is enforced by CheckpointStatement, after the
    # signature verifies -- never before.
    _check_map(statement, f"{where}.statement", (), tuple(statement),
               restatement=False)
    # BV-025. Carried as made, with the construction NAMED beside it. The name
    # is not resolved here -- `parse` reaches no verdict and resolving a
    # construction is a step in reaching one.
    _bstr(value["signature"], f"{where}.signature")
    _text(value["signature_form"], f"{where}.signature_form")


def _check_bound(size: int, where: str, max_bundle_bytes: int | None) -> None:
    """`BV-023`, and it runs before anything walks the bytes.

    > **`BV-003` step 1 is "decode the bytes." That decode is itself a walk over
    > attacker-supplied structure, and it happens BEFORE any signature, any
    > bound read from signed bytes, and every protection `BV-022` provides.**

    **`max_bundle_bytes` is a provisioned input WITH NO DEFAULT**, exactly like
    the recognised encodings, the key directory, the witness trust list and the
    token verifiers. `None` means *nobody chose*, and it is refused rather than
    filled in — **`BV-023`'s measured reference sizes are given in the
    specification as measurements of one bundle and explicitly not as a limit**,
    so reading them as one here would make this verifier the party that decided.
    """
    if max_bundle_bytes is None:
        raise BundleError(
            "bundle-size-bound-not-provisioned",
            "a maximum accepted size is required and there is no default; this "
            "verifier was not given one, so it will not begin a decode it has no "
            "bound for")
    if not isinstance(max_bundle_bytes, int) or isinstance(max_bundle_bytes, bool) \
            or max_bundle_bytes < 1:
        raise BundleError("bundle-size-bound-not-provisioned",
                          f"max_bundle_bytes must be a positive int, got "
                          f"{max_bundle_bytes!r}")
    if size > max_bundle_bytes:
        raise BundleError(
            "bundle-too-large",
            f"{where} is {size} bytes against a provisioned bound of "
            f"{max_bundle_bytes}; refused UNREAD")


def read(path, *, max_bundle_bytes: int | None) -> bytes:
    """Return a bundle's bytes, or refuse **without reading them**.

    `BV-023`: *"Bytes beyond it are refused unread."* **A `parse` that receives
    `bytes` has already been handed everything the attacker sent**, so the
    clause's own word cannot be honoured at that boundary alone. The size is
    taken from the filesystem, the bound is applied, and the file is opened only
    if it passes.

    *`BV-022` protects the walks a verifier performs on structure it has
    decoded; `BV-023` is what stops the decoder being the one unbounded walk
    that all the others sit behind — and a reader that slurps the file to
    measure it has already performed that walk.*
    """
    size = os.path.getsize(path)
    _check_bound(size, f"{path}", max_bundle_bytes)
    with open(path, "rb") as handle:
        return handle.read()


def parse(data: bytes, *, recognised_encodings: frozenset[str],
          max_bundle_bytes: int | None) -> Bundle:
    """Parse a bundle per `BV-002`/`BV-003`. Raises `BundleError` on refusal.

    `recognised_encodings` and `max_bundle_bytes` both have **no default**
    (`BV-004`, `BV-023`): a verifier that invents an identifier and then
    recognises it has certified its own guess, and one that invents a size bound
    has made an operator's decision on their behalf.

    **`BV-003`'s order, and it is not negotiable:**

    0. **refuse anything past the provisioned bound** — `BV-023`, which sits
       underneath step 1 because step 1 is itself a walk over attacker-supplied
       structure;
    1. **decode** under the strict profile — `cbor.BUNDLE`, which is `BV-005`'s
       table in full;
    2. **re-encode and compare byte-for-byte** — refused here, *before the
       bundle's own claim about its encoding is consulted*. `H-2` reported this
       inversion, and it was ratified as **stricter, not weaker**: the
       round-trip is a property of the bytes and needs no permission from the
       document to be checked;
    3. **read `encoding_id`**, item 0, and refuse unless provisioned;
    4. **only then** interpret item 1.
    """
    _check_bound(len(data), "the bundle", max_bundle_bytes)

    try:
        value = assert_round_trip(data, profile=BUNDLE_PROFILE)
    except CborError as exc:
        if exc.code == "cbor-tag-not-permitted" and exc.tag_number == COSE_SIGN1_TAG \
                and exc.offset == 0:
            # BV-001. Signing the container adds no evidence -- the operator has
            # already signed the record -- while inviting "the bundle verifies"
            # to be heard as "the record verifies".
            #
            # ⚠ This branch survives `cbor.BUNDLE` refusing every tag but 2 and
            # 3. Without it, BV-001's refusal would be swallowed by BV-005's,
            # and the more specific finding -- THIS container is signed -- would
            # be reported as the more general one. *A refusal that does not say
            # which kind of mistake it found has thrown away the reason it was
            # worth naming.*
            raise BundleError(
                "bundle-is-signed",
                "the outermost item is a COSE_Sign1; a bundle is a "
                "container and an UNSIGNED one") from None
        raise BundleError("bundle-not-deterministic", str(exc)) from None

    if isinstance(value, Tag):
        raise BundleError("bundle-not-an-array",
                          f"the outermost item is tag {value.number}, not an array")
    if not isinstance(value, list):
        raise BundleError("bundle-not-an-array",
                          f"the outermost item is {type(value).__name__}, not an array")
    if len(value) != 2:
        raise BundleError(
            "bundle-wrong-arity",
            f"a bundle is [encoding_id, body], exactly two items; got "
            f"{len(value)}. No other outer shape is a bundle")

    encoding_id = value[0]
    if not isinstance(encoding_id, str):
        raise BundleError("bundle-encoding-id-not-text",
                          f"item 0 is {type(encoding_id).__name__}, not a text string")
    if encoding_id not in recognised_encodings:
        raise BundleError(
            "bundle-encoding-unrecognised",
            f"{encoding_id!r} is not among the encodings this verifier was "
            f"provisioned to recognise ({sorted(recognised_encodings) or 'none'}); "
            "stopping rather than assuming a profile")

    body = _check_map(value[1], "body", BODY_REQUIRED, BODY_OPTIONAL)

    bundle_version = _uint(body["bundle_version"], "body.bundle_version")
    if bundle_version not in RECOGNISED_BUNDLE_VERSIONS:
        raise BundleError(
            "bundle-version-unknown",
            f"bundle_version {body['bundle_version']!r}; this verifier will not "
            "guess a field set for a version it does not implement. Recognised: "
            f"{sorted(RECOGNISED_BUNDLE_VERSIONS)}")

    # ⚠ **ONE VERSION, ONE IDENTIFIER**. `BV-003` step 3 reads item
    # 0 and step 4 reads the body; a bundle naming one form in each has told a
    # reader two things, and the step that reads the first never sees the
    # second. Refused rather than resolved in favour of either.
    if encoding_id != ENCODING_ID_BY_BUNDLE_VERSION[bundle_version]:
        raise BundleError(
            "bundle-encoding-version-mismatch",
            f"item 0 is {encoding_id!r} and the body declares bundle_version "
            f"{bundle_version}, whose identifier is "
            f"{ENCODING_ID_BY_BUNDLE_VERSION[bundle_version]!r}")

    record = _check_map(body["record"], "record", RECORD_KEYS)
    _bstr(record["canonical_bytes"], "record.canonical_bytes")
    _text(record["form_tag"], "record.form_tag")
    _bstr(record["signature"], "record.signature")
    _text(record["signature_form"], "record.signature_form")
    _uint(record["leaf_index"], "record.leaf_index")
    if not isinstance(record["envelope"], dict):
        raise BundleError("bundle-field-type", "record.envelope is not a map")

    _check_checkpoint(body["checkpoint"], "checkpoint")
    _check_proof(body["inclusion_proof"], "inclusion_proof")

    receipts = body["receipts"]
    if not isinstance(receipts, list):
        raise BundleError("bundle-field-type", "receipts is not an array")
    for i, element in enumerate(receipts):
        if not isinstance(element, dict):
            raise BundleError("bundle-field-type", f"receipts[{i}] is not a map")

    witness_keys = body["witness_keys"]
    if not isinstance(witness_keys, list):
        raise BundleError("bundle-field-type", "witness_keys is not an array")
    for i, element in enumerate(witness_keys):
        _check_map(element, f"witness_keys[{i}]", WITNESS_KEY_KEYS)
        _text(element["witness_key_ref"], f"witness_keys[{i}].witness_key_ref")
        _bstr(element["key_material"], f"witness_keys[{i}].key_material")
        _text(element["format"], f"witness_keys[{i}].format")

    if "prior_checkpoint" in body:
        _check_checkpoint(body["prior_checkpoint"], "prior_checkpoint")
    if "consistency_proof" in body:
        _check_proof(body["consistency_proof"], "consistency_proof")
    if "key_directory_hint" in body:
        _text(body["key_directory_hint"], "key_directory_hint")
    if "json_view" in body:
        _text(body["json_view"], "json_view")

    notes = []
    if "key_directory_hint" in body:
        # BV-012. Recorded, never followed. "An offline verification must not
        # consult it, and a verification that did is not offline."
        notes.append("key_directory_hint present; NOT consulted (BV-012)")
    if "json_view" in body:
        # BV-013. "A verifier that reads it has verified nothing."
        notes.append("json_view present; never verified against (BV-013)")
    if not receipts:
        notes.append("receipts is empty: no receipt is present (BV-008 section 8)")

    return Bundle(encoding_id=encoding_id, body=body, notes=notes)
