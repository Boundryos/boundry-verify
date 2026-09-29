"""The verification chain — T-2, reordered at T-3+ to §8's own sequence.

The specification states the procedure: resolve the era key
→ **check the checkpoint signature** → read `head_construction_id` → recompute
the leaf → verify inclusion → verify the receipt.

**T-2 verified inclusion BEFORE the checkpoint signature.** That is not merely
out of order: `ERR-P3-008`'s `ALTERED` is defined as *"a valid attestation
exists and the content no longer matches it"*, and whether a valid attestation
exists is exactly what the checkpoint-signature rung decides. Checking
inclusion first makes `ALTERED` undeterminable, so the record could only ever be
reported with the weaker `REFUTED`. **Following §8's order is what lets the
ladder tell the two apart.**

⚠ Two rungs are exercised against SYNTHETIC material and are labelled as such
at every point they are reported: nothing has been witnessed and no checkpoint
has been emitted.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .canonical_form import canonical_bytes, content_hash
from .checkpoint import (CheckpointError, CheckpointStatement,
                         resolve_construction, verify_checkpoint_signature,
                         witness_message)
from .ed25519 import verify as ed25519_verify
from .envelope_form import envelope_canonical_bytes
from .keys import KeyDirectory, KeyDirectoryError
from .merkle import MerkleError
from .receipt import Receipt, ReceiptError
from .verdict import (ALTERED, ATTESTED, INDETERMINATE, REFUTED, UNATTESTED,
                      Report, Verdict)

__all__ = ["verify_record", "SYNTHETIC_RUNGS"]

SYNTHETIC_RUNGS = ("checkpoint", "witness receipt")

_UNBOUND = (
    "the envelope's recorded timestamp, submitter attribution and ledger "
    "ordinal — these reach no canonical byte by any path and have no "
    "cryptographic protection whatsoever (CEF-009, CF §9)"
)
_STOP = "anything further — the ladder stops here"


def verify_record(
    *,
    payload: Any,
    payload_hash: str,
    envelope_kind: str,
    position: int,
    prev_envelope_hash: str,
    is_genesis: bool,
    signature: bytes,
    era: str,
    directory: KeyDirectory,
    leaf_index: int | None = None,
    audit_path: Sequence[bytes] | None = None,
    checkpoint: Mapping[str, Any] | None = None,
    checkpoint_signature: bytes | None = None,
    receipt: Mapping[str, Any] | None = None,
) -> Report:
    """Run the ladder. Returns a Report of Verdicts — never a boolean.

    ⚠ AND NEVER AN EXCEPTION (`ERR-P4-002`, DRAFT). Every path out of this
    function returns a Report. An unhandled exception returns nothing, and a
    caller wrapping this in `try` would read a crash as a refusal -- so an
    instrument that broke and a record that failed would become the same fact.
    """
    report = Report()
    try:
        return _verify_record(report, payload=payload, payload_hash=payload_hash,
                              envelope_kind=envelope_kind, position=position,
                              prev_envelope_hash=prev_envelope_hash,
                              is_genesis=is_genesis, signature=signature, era=era,
                              directory=directory, leaf_index=leaf_index,
                              audit_path=audit_path, checkpoint=checkpoint,
                              checkpoint_signature=checkpoint_signature,
                              receipt=receipt)
    except Exception as exc:                       # noqa: BLE001 -- deliberate
        # ⚠ THE BOUNDARY CATCH. Broad by design: the class of fault this exists
        # for is the one nobody anticipated. A narrow except would catch the
        # exceptions we already thought of, which are the ones already handled.
        report.add(Verdict(
            "verifier", INDETERMINATE, established=(),
            not_established=("anything whatsoever about this record — this "
                             "verifier did not complete",),
            detail=f"{type(exc).__name__}: {exc}. THIS IS A FAULT IN THE "
                   "VERIFIER, not a finding about the record. It is not a "
                   "refusal and must not be reported as one"))
        return report


def _verify_record(
    report: Report,
    *,
    payload: Any,
    payload_hash: str,
    envelope_kind: str,
    position: int,
    prev_envelope_hash: str,
    is_genesis: bool,
    signature: bytes,
    era: str,
    directory: KeyDirectory,
    leaf_index: int | None = None,
    audit_path: Sequence[bytes] | None = None,
    checkpoint: Mapping[str, Any] | None = None,
    checkpoint_signature: bytes | None = None,
    receipt: Mapping[str, Any] | None = None,
) -> Report:

    # --- the record's own rungs ------------------------------------------
    try:
        payload_bytes = canonical_bytes(payload)
    except Exception as exc:
        report.add(Verdict("canonical bytes", REFUTED, established=(),
                           not_established=(_STOP,),
                           detail=f"the payload has no canonical form: {exc}"))
        return report
    report.add(Verdict(
        "canonical bytes", ATTESTED,
        established=("the payload reproduces a canonical byte string under "
                     "SPEC_Boundry_Canonical_Form_v1",),
        not_established=("that these bytes are what the operator sealed — that is "
                         "a later rung",
                         "the payload's meaning, correctness or authorisation")))

    if content_hash(payload) != payload_hash:
        report.add(Verdict(
            "payload hash", REFUTED, established=(), not_established=(_STOP,),
            detail="the stated payload_hash does not match the hash of the "
                   "payload's canonical bytes; no attestation has been validated "
                   "at this point, so this is refuted evidence and not ALTERED"))
        return report
    report.add(Verdict(
        "payload hash", ATTESTED,
        established=("the stated payload_hash is the SHA-256 of those canonical bytes",),
        not_established=("who computed it, or when",)))

    # §8 step 1 — resolve the era key from the directory, obtained independently
    try:
        key = directory.resolve(era)
    except KeyDirectoryError as exc:
        report.add(Verdict("era signature", UNATTESTED, established=(),
                           not_established=("that any designated key signed this record", _STOP),
                           detail=f"the era key could not be resolved ({exc})"))
        return report

    # CF-ENV-001: the signature covers the canonical bytes of the payload ALONE.
    if not ed25519_verify(key.public_key, payload_bytes, signature):
        report.add(Verdict(
            "era signature", UNATTESTED, established=(),
            not_established=(f"that the era {era!r} key attested to these bytes", _STOP),
            detail=f"the signature does not verify under the era {era!r} key. This "
                   f"is absence of attestation by the designated key, not a finding "
                   f"of falsity (CP-008)"))
        return report
    sig_not = [
        "WHERE this envelope sits: CF-ENV-003 — two envelopes at different "
        "positions carrying identical payloads have identical signatures, so a "
        "signature does not attest to position",
        _UNBOUND,
        "that the record is current, unsuperseded or correct (KD-008)",
    ]
    # ⚠⚠ **A BRANCH STOOD HERE AND NO INPUT COULD REACH IT** (the
    # claim is INVERTED where it stood, never silently deleted). It read:
    #
    #     if key.compromised:
    #         sig_not.insert(0, "that the operator produced it — this era is
    #                           marked COMPROMISED, ...")
    #
    # `key` has one source — `directory.resolve(era)` above — and `resolve`
    # REFUSES a compromised era outright (`keys.py`: `verifies` is
    # `status in (CURRENT, RETIRED)`, and `resolve` raises otherwise). So
    # `key.compromised` was False on every input that ever got here, and the
    # qualification never once appeared in a verdict.
    #
    # **Ruled: a compromised era stays refused at resolution.** No verdict is
    # ever produced under one, qualified or otherwise, so there is no verdict
    # for this sentence to qualify. The refusal is the stronger behaviour and
    # its absence from this list is now what says so.
    #
    # > ***DEAD CODE THAT DESCRIBES A SAFER WORLD THAN THE ONE THAT RUNS IS
    # > NOT HARMLESS: IT READS LIKE A GUARANTEE, AND IT IS SCENERY.***
    report.add(Verdict("era signature", ATTESTED,
                       established=(f"the payload's canonical bytes were signed by "
                                    f"the era {era!r} key",),
                       not_established=tuple(sig_not)))

    if checkpoint is None:
        report.add(Verdict(
            "checkpoint", UNATTESTED, established=(),
            not_established=("that this record is under any published head",
                             "any ordering or time claim beyond the operator's own"),
            detail="no checkpoint supplied; order and time rest on the operator alone"))
        report.add(Verdict(
            "witness receipt", UNATTESTED, established=(),
            not_established=("when this record's head was seen by any party other "
                             "than the operator",
                             "any independent time binding"),
            detail="no checkpoint, therefore no receipt"))
        return report

    try:
        stmt = CheckpointStatement(checkpoint)
    except CheckpointError as exc:
        report.add(Verdict("checkpoint", REFUTED, established=(),
                           not_established=(_STOP,), detail=str(exc)))
        return report

    # §8 step 2 — the checkpoint signature, BEFORE its head is used for anything.
    checkpoint_attested = False
    if checkpoint_signature is None:
        report.add(Verdict("checkpoint signature", UNATTESTED, established=(),
                           not_established=("that the operator vouches for this head", _STOP),
                           detail="no checkpoint signature supplied"))
        return report
    try:
        ok = verify_checkpoint_signature(stmt, checkpoint_signature, directory)
    except (CheckpointError, KeyDirectoryError) as exc:
        report.add(Verdict("checkpoint signature", REFUTED, established=(),
                           not_established=(_STOP,), detail=str(exc)))
        return report
    if not ok:
        report.add(Verdict(
            "checkpoint signature", REFUTED, established=(), not_established=(_STOP,),
            detail="a checkpoint signature was supplied and does not verify under "
                   "its era key"))
        return report
    checkpoint_attested = True
    report.add(Verdict(
        "checkpoint signature [SYNTHETIC]", ATTESTED,
        established=(f"the checkpoint statement was signed by the era {stmt.era!r} key",),
        not_established=("SYNTHETIC MATERIAL — nothing has been emitted or witnessed",
                         "any independent time: CP-002 — kernel_time is the "
                         "OPERATOR'S ASSERTION and carries no independent weight",
                         "that the operator did not present a different history to "
                         "someone else — only a witness constrains that")))

    # §8 step 3 — read head_construction_id; never assume, never fall back.
    try:
        construction = resolve_construction(stmt)
    except CheckpointError as exc:
        report.add(Verdict(
            "head construction", UNATTESTED, established=(), not_established=(
                "that this record is under the checkpoint's head — the construction "
                "that produced it is unknown to this verifier", _STOP),
            detail=f"{exc} (not evaluable rather than refuted: nothing was checked "
                   f"and failed)"))
        return report

    # §8 step 4 — recompute the leaf.
    try:
        cef = envelope_canonical_bytes(
            envelope_kind=envelope_kind, payload_hash=payload_hash, position=position,
            prev_envelope_hash=prev_envelope_hash, is_genesis=is_genesis)
    except Exception as exc:
        report.add(Verdict("envelope leaf", REFUTED, established=(),
                           not_established=(_STOP,),
                           detail=f"the canonical envelope form is invalid: {exc}"))
        return report
    report.add(Verdict(
        "envelope leaf", ATTESTED,
        established=("the envelope reduces to a canonical five-key leaf (CEF-001)",
                     "the leaf commits to the payload hash, kind, position and, "
                     "transitively, the entire predecessor history (CEF-004)"),
        not_established=(_UNBOUND, "that this leaf is in any tree — that is the next rung")))

    # §8 step 5 — inclusion, with tree_size = ledger_ordinal (CP-012).
    if leaf_index is None or audit_path is None:
        report.add(Verdict("inclusion proof", UNATTESTED, established=(),
                           not_established=("that this record is under the checkpoint's head",),
                           detail="no inclusion proof supplied"))
        return report
    try:
        construction["verify_inclusion"](
            construction["leaf_hash"](cef), leaf_index, stmt.ledger_ordinal,
            list(audit_path), bytes.fromhex(stmt.head_hash))
    except MerkleError as exc:
        # ERR-P3-008: a VALID attestation exists (the checkpoint signature verified
        # at the rung above) and this content is not under it -> ALTERED. Without
        # §8's ordering this could only have been reported as REFUTED.
        outcome = ALTERED if checkpoint_attested else REFUTED
        report.add(Verdict(
            "inclusion proof [SYNTHETIC]", outcome, established=(),
            not_established=("when the content and the attestation diverged",
                             "which of them is the original", _STOP),
            detail=(f"a signed checkpoint attests to head {stmt.head_hash[:12]}… and "
                    f"this record is not under it: {exc}")
                   if checkpoint_attested else str(exc)))
        return report
    report.add(Verdict(
        "inclusion proof -> checkpoint head [SYNTHETIC]", ATTESTED,
        established=(f"the leaf is at index {leaf_index} of the tree of size "
                     f"{stmt.ledger_ordinal} whose root is the checkpoint's head_hash, "
                     f"under construction {stmt.head_construction_id!r}",),
        not_established=("SYNTHETIC MATERIAL — no checkpoint has ever been emitted "
                         "into the chain",
                         "the content, correctness or authorisation of any record "
                         "beneath the head (CP-010)")))

    # §8 step 6 — the receipt.
    if receipt is None:
        report.add(Verdict(
            "witness receipt", UNATTESTED, established=(),
            not_established=("when this record's head was seen by any party other "
                             "than the operator",
                             "any independent time binding — order and time rest on "
                             "the operator alone"),
            detail="unwitnessed (no receipt supplied); this is not a finding against "
                   "the record"))
        return report
    try:
        rec = Receipt(receipt)
    except ReceiptError as exc:
        report.add(Verdict("witness receipt", REFUTED, established=(),
                           not_established=("that any witness saw this checkpoint",),
                           detail=f"a receipt was supplied and is not well-formed: {exc}"))
        return report
    if not rec.attests_to(stmt):
        report.add(Verdict(
            "witness receipt", REFUTED, established=(),
            not_established=("that any witness saw THIS checkpoint",),
            detail="the receipt attests to a different digest, so it does not attest "
                   "to this checkpoint however valid it may be in itself"))
        return report
    report.add(Verdict(
        "witness receipt [SYNTHETIC]", ATTESTED,
        established=("the receipt is a well-formed five-key form (ERR-P3-005)",
                     "its attested_digest IS the SHA-256 of this checkpoint "
                     "statement's canonical bytes, recomputed here rather than "
                     "taken from the receipt (ERR-P3-004)"),
        not_established=("SYNTHETIC MATERIAL — no witness has ever been contacted",
                         *rec.unverifiable_because,
                         "that the certificate belongs to a trusted authority, or "
                         "that the signer is independent of the operator: a receipt "
                         "an operator minted for themselves would reach this same "
                         "result (ERR-CP-001)")))
    return report
