"""The witness trust list — STOP-C, and `D5-e` in full.

**Built from the verification-bundle specification (as amended), `ERRATA_P3_02`
and the checkpoints-and-receipts specification alone.** The kernel repository has not
been read.

## ⚠ Why this module exists at all, and why it was held back until now

A ruling recorded the STOP-B result exactly: **an internally perfect self-minted
bundle returned `UNATTESTED` because `witness_keys` was never read — the right
answer for the wrong reason. Correct by omission is not a property.**

**This module makes it a property.** The trust list is real, the anchored path
executes, and `ATTESTED` is reachable — so `UNATTESTED` on a forged bundle is
now an *outcome of anchoring* rather than an absence of code.

**It was designed without reference to the bundle's shape**, deliberately: a
trust list whose structure was derived from the container it is meant to be
independent of is `SHARED-ANCESTOR` at one remove. `Anchor` carries what a
witness's key is, not what a bundle says about it.

## ⚠ The structural guarantee, and it is in the SIGNATURES

`BV-010`: a bundle-supplied key may never raise a verdict. **`verify_token`
takes an `Anchor` and has no parameter through which bundle-supplied key
material could arrive** — not one that is ignored, one that does not exist.
`agreement_finding` is the only function that touches the bundle's copy, and it
returns TEXT, never a key and never a verdict. *(`BV-011`: disagreement is a
named finding; it does not lower the verdict because it is not evidence about
the record, and it does not raise it because nothing a bundle supplies ever
does.)*

**⚠ `BV-011` was CORRECTED and `agreement_finding` was rebuilt for it:
it compares the KEYS the two sides denote, not the bytes they spell them with.**
*The reduction it uses is `key_forms`', which is also what a token checker must
use on the anchor — because a checker that reduced for the comparison and not
for the verification would have moved the disagreement rather than removed it.*

**⚠ Nothing above names a witness kind, and the suite asserts that textually.**
*`BV-019` keeps every checker provisioned; a module that mentions one is one
edit away from registering it.*

## ⚠ The token is opaque, so `ATTESTED` needs more than an anchor

`ERR-P3-005` carries `witness_token` **"verbatim and deliberately opaque to
Boundry"** — a DER `TimeStampToken`, a Rekor entry. **So section 12 step 7,
*"verify each receipt under an anchored witness key"*, is NOT executable for
either named `witness_kind` without implementing that witness's own format**,
which an earlier ruling already placed outside this pack.

**Anchoring is therefore necessary and not sufficient.** `token_verifiers` is a
second provisioned input, `witness_kind` to a checker, with **no default and no
built-in kinds** — this pack implements the anchoring and the dispatch, not any
witness's wire format. An anchored receipt whose kind has no checker is
`UNATTESTED` under its own reason code, **never `ATTESTED`**, because *a
verifier that treats "I could not check this" as "this checks out" has inverted
the one distinction `ERR-P3-008` exists to preserve.*
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from . import key_forms

__all__ = ["consistency_over_stream", "CONSISTENCY_VERIFIED",
           "CONSISTENCY_FAILED", "CONSISTENCY_ERA_BOUNDARY",
           "CONSISTENCY_PROOF_ABSENT", "CONSISTENCY_PROOF_WITHHELD",
           "CONSISTENCY_CONSTRUCTION_DIFFERS",
           "CONSISTENCY_CONSTRUCTION_UNKNOWN",
           "CONSISTENCY_VERSION_DIFFERS",
           "continuity_report", "CONTINUITY_CONTINUOUS",
           "CONTINUITY_DECREASED", "CONTINUITY_ERA_CROSSED", "CONTINUITY_REPEATED",
           "SUBMISSION", "OBSERVATION", "OBSERVATION_GRADES",
           "HONEST_LIMB", "INDEPENDENT", "OPERATOR_HELD",
           "INDEPENDENCE_VALUES", "LEGACY_TRUST_LIST_DIGESTS", "CUSTODY_REFUSALS",
           "custody_problems",
           "Anchor", "WitnessTrustList", "TokenVerifier", "REASONS",
           "REASON_SEPARATOR", "reason_code", "agreement_finding", "verify_token",
           "TOKEN_VERIFIED", "TOKEN_REFUSED_TOKEN_DEFECT",
           "TOKEN_REFUSED_CHECKER_SHORT", "TOKEN_CLASSES",
           "NO_CHECKER", "REFUSAL_CLASS_ABSENT", "RESULTS",
           "SPECIFICATION_FINDING"]

#: Reason codes for a witness rung that did not reach `ATTESTED`. `BV-010`
#: requires "no receipt" and "a receipt whose witness this verifier does not
#: anchor" to be distinguishable; `H-8` adds a third that is neither.
#:
#: **⚠ TWO, and they are not the same kind of addition.**
#: `witness-checker-cannot-evaluate` is this verifier's spelling of `BV-020`'s
#: FIFTH FACT. `witness-checker-refusal-class-absent` is
#: `BV-020`'s SELF-REPAIRING clause firing: a fact no member of the closed set
#: names, reported as a specification finding rather than absorbed into
#: `REFUTED`.
REASONS = (
    "witness-no-receipt",
    "witness-no-trust-list",
    "witness-not-anchored",
    "witness-kind-not-implemented",
    "witness-checker-cannot-evaluate",
    "witness-checker-refusal-class-absent",
    "witness-token-does-not-verify",
    "witness-anchored-and-verified",
)

# ---------------------------------------------------------------------------
# ⚠ `BV-028`'s OPERATIONAL BOUNDARY — the class of a refusal, added
# later.
#
# > *"A token checker returning ONE BOOLEAN CANNOT BE CONFORMANT WITH THIS
# > CLAUSE. When it refuses, the refusal is either THE TOKEN IS WRONG ... or WE
# > ARE SHORT ... THE CALLER CANNOT TELL THEM APART FROM A BOOLEAN, AND MUST NOT
# > GUESS."*
#
# So the class travels on its own channel and NOT inside a finding. `BV-024`
# requires the finding channel to be incapable of altering a verdict; a class
# read out of finding TEXT would be a caller branching on a finding, which is
# the same defect wearing the repair's clothes. **The class is a first-class
# return value with a closed vocabulary; the findings stay inert.**
# ---------------------------------------------------------------------------

#: The token verified. **`True` is still accepted for this and only this**: the
#: clause constrains a REFUSAL, and a bare `True` carries no ambiguity to
#: resolve. *Widening the boundary past the clause would be minting
#: specification, which is the thing the ruling declined to do.*
TOKEN_VERIFIED = "token-verified"

#: *The token is wrong.* Evidence was supplied and it failed — an imprint over
#: another digest, a signature that does not verify, an algorithm pairing the
#: standard forbids. **`ERR-P3-008`: this is `REFUTED`.**
TOKEN_REFUSED_TOKEN_DEFECT = "token-refused-token-defect"

#: *We are short.* The checker executed and holds no implementation for
#: something the token or the anchor declares — an algorithm, a representation,
#: a parameter. **`BV-028`: this is `UNATTESTED`, and never `REFUTED`.**
TOKEN_REFUSED_CHECKER_SHORT = "token-refused-checker-short"

#: Everything a conforming `TokenVerifier` may return as its first value.
TOKEN_CLASSES = (TOKEN_VERIFIED, TOKEN_REFUSED_TOKEN_DEFECT,
                 TOKEN_REFUSED_CHECKER_SHORT)

#: No checker was provisioned for this witness kind. **Only `verify_token` can
#: produce it** — a checker that does not exist cannot report about itself.
NO_CHECKER = "no-checker"

#: ⚠ A checker refused WITHOUT declaring which class it meant — the bare
#: boolean `BV-028` names. **Only `verify_token` can produce it.**
#:
#: This is not `TOKEN_REFUSED_CHECKER_SHORT`: that fact asserts the checker
#: holds no implementation, and here we do not know that. It is a fact **no
#: member of `BV-020`'s closed set names**, so `BV-020`'s self-repairing clause
#: governs: *report it as a specification finding and do not absorb it into
#: `REFUTED`.* **Guessing either way would be the caller deciding what the
#: checker meant, which `BV-024` reserves to the checker.**
REFUSAL_CLASS_ABSENT = "refusal-class-absent"

#: Everything `verify_token` may return as its first value. **Closed.** A caller
#: dispatches on this and on nothing else.
RESULTS = TOKEN_CLASSES + (NO_CHECKER, REFUSAL_CLASS_ABSENT)

#: The sentence `REFUSAL_CLASS_ABSENT` carries, so the specification finding is
#: legible to a reader who has neither clause to hand.
SPECIFICATION_FINDING = (
    "SPECIFICATION FINDING (BV-020, self-repairing clause): the provisioned "
    "checker refused without declaring the CLASS of its refusal, so this "
    "verifier cannot tell 'the token is wrong' from 'we are short'. BV-028's "
    "operational boundary makes such a checker non-conforming. This is NOT "
    "evidence about the record and MUST NOT be read as REFUTED"
)

#: A checker for one `witness_kind`. Given the anchored key material, its
#: declared format, the opaque token bytes and the digest `ERR-P3-004` says the
#: witness attested to, it returns whether the token verifies. **Provisioned by
#: the verifier's operator; this pack ships none.**
#:
#: It returns **a member of `TOKEN_CLASSES`, or `(class, findings)` where
#: `findings` is a SEQUENCE of strings** — things the checker LEARNED and is
#: reporting without judging. *(The class was added
#: under `BV-028`'s operational boundary.)*
#:
#: **`True` and `(True, findings)` remain accepted and mean `TOKEN_VERIFIED`.**
#: **`False` in either shape is a NON-CONFORMING refusal** and is reported as
#: `REFUSAL_CLASS_ABSENT` — never guessed into one of the two classes.
TokenVerifier = Callable[[bytes, str, bytes, bytes], object]

#: What separates a reason CODE from any findings appended to it.
REASON_SEPARATOR = " · "


def reason_code(reason: str) -> str:
    """The `REASONS` member at the head of a reason.

    ***THE ONLY PART OF A REASON ANY CALLER MAY BRANCH ON*** — the
    normative half. Everything after the separator is a finding, and **a finding
    may never alter a verdict.**

    The split is on the FIRST separator, so a finding that contains one cannot
    change what the head reads as. *Part of a finding's text comes from the
    token, which is attacker-supplied; the head does not.*
    """
    return reason.split(REASON_SEPARATOR, 1)[0]


def _classify(head) -> str:
    """One checker's declared outcome, mapped into `RESULTS`. **Never guesses.**

    `BV-028`'s operational boundary: a refusal that does not name its class is
    not conformant, and the caller *"MUST NOT GUESS."* So `False` maps to
    `REFUSAL_CLASS_ABSENT` — a fact about the CHECKER's contract — rather than
    to either class it might have meant.
    """
    if head is True:
        return TOKEN_VERIFIED
    if head is False:
        return REFUSAL_CLASS_ABSENT
    if head in TOKEN_CLASSES:
        return head
    raise TypeError(
        f"a TokenVerifier's outcome is one of {list(TOKEN_CLASSES)} (or True "
        f"for {TOKEN_VERIFIED!r}); got {head!r}. A refusal carries the "
        "class of its refusal, and this channel is where it carries it")


def _normalise(result) -> tuple[str, tuple[str, ...]]:
    """A checker's return, in the two shapes a ruling admits and no others.

    **The head is now a CLASS rather than a bool**. The second
    shape is unchanged and the findings channel is untouched: it still carries
    text, and it still decides nothing.
    """
    if isinstance(result, bool) or (isinstance(result, str)
                                    and result in TOKEN_CLASSES):
        return _classify(result), ()
    if not isinstance(result, (tuple, list)) or len(result) != 2:
        raise TypeError(
            "a TokenVerifier returns an outcome class, or (class, findings) "
            "with findings a sequence of strings; got "
            f"{type(result).__name__}")
    verified, findings = result
    if isinstance(findings, (str, bytes, bytearray)):
        # ⚠ A bare string IS iterable, so this would otherwise report one
        # finding per LETTER. The ruling said "a sequence of strings, not one string"
        # and this is the line that makes the difference detectable.
        raise TypeError(
            "findings must be a SEQUENCE of strings, not one string: a bare "
            "string iterates into characters, so a checker returning one would "
            "report a finding per letter")
    return _classify(verified), tuple(str(f) for f in findings)


def _with_findings(code: str, findings: tuple) -> str:
    """Append findings to a reason code. **The code stays at the head.**"""
    return REASON_SEPARATOR.join((code,) + findings) if findings else code


@dataclass(frozen=True)
class Anchor:
    """One witness this verifier has been provisioned to trust.

    *"Independently obtained, long-lived, nothing to do with any bundle."*
    """

    witness_key_ref: str
    key_material: bytes
    format: str

    # --- WIT-002 custody record ----------------------------
    #: WHO generated the key and WHERE it is held. Free text: this is an
    #: attested claim about the world, not a checkable fact (see `HONEST_LIMB`).
    custodian: str | None = None
    #: Whether ANY operator-side path to the private half exists. `None` means
    #: undeclared, which is NOT the same fact as declared-False.
    operator_recoverable: bool | None = None
    #: `independent` | `operator-held`. DERIVABLE from the two above and refused
    #: when it contradicts them — see `custody_problems`.
    independence: str | None = None

    #: ⚠ `WIT-001` v2's observation grade — `submission` | `observation`.
    #:
    #: CARRIED HERE AND NOT ON THE RECEIPT, and the reason is the same one
    #: given for custody: `ERR-P3-005`'s five entries are CLOSED, and a
    #: grade is a property of the WITNESSING ARRANGEMENT — how this witness gets
    #: its checkpoints — not of an individual observation. Two receipts from one
    #: witness cannot disagree about it.
    #:
    #: ⚠ SO `WIT-001` v2's sentence "receipts carry their grade" CANNOT BE
    #: SATISFIED as written: the receipt set is closed, exactly as it was for
    #: `independence`. Reported; the anchor is where the fact
    #: truthfully lives.
    observation_grade: str | None = None

    #: ⚠ `WIT-001` v3: a grade-(b) anchor additionally attests its RETRIEVAL
    #: PRACTICE — that the witness fetches by its own act, on its own schedule.
    #:
    #: This is an ATTESTED claim, exactly as custody is, and the clause is right
    #: to label it so: no artefact a reader can hold establishes it. It sits
    #: beside `custodian` for that reason — same kind of fact, same place.
    retrieval_practice: str | None = None


#: `WIT-002`'s honest limb, carried where the code is so it cannot drift from the
#: clause: **cryptography verifies the signature under the anchored key; it does
#: not verify custody.** A reader of `independence: independent` is trusting the
#: declaration's attestor.
#:
#: ⚠ NARROWED: the draft said cryptography can NEVER verify custody.
#: That is false as an absolute — HSM and TPM key-attestation certificates are
#: cryptographic evidence of generation locus and non-extractability, which are
#: custody facts. What cryptography cannot verify is the CONTROL RELATION
#: `WIT-002` actually tests: who directs, or can compel, the party holding the
#: key. The narrower claim is the true one and is the one stated here.
HONEST_LIMB = (
    "the custody record is an attested claim about the world; cryptography "
    "verifies the signature under the anchored key and cannot verify who "
    "controls, directs or can compel the holder of it"
)

#: `independence` values this version recognises.
INDEPENDENT = "independent"
OPERATOR_HELD = "operator-held"
INDEPENDENCE_VALUES = (INDEPENDENT, OPERATOR_HELD)

#: `WIT-001` v2's two grades. Only `OBSERVATION` makes a witness's silence
#: evidence; `CP-009`'s cadence figure is defined only over it.
SUBMISSION = "submission"
OBSERVATION = "observation"
OBSERVATION_GRADES = (SUBMISSION, OBSERVATION)

#: ⚠ THE REGISTERED LEGACY SET (`KD-013`'s migration pattern).
#:
#: Anchors that predate the custody record are recognised BY REGISTERED DIGEST OF
#: THE ARTEFACT THAT CARRIES THEM, never by re-deriving from an editable copy —
#: because the only one canon actually holds lives in `INTEROP/`, which is FROZEN
#: and cannot be edited to add the fields. A digest is the one handle that does
#: not require touching it.
#:
#: Measured: `INTEROP/oob/witness_trust_list.json`, 530 bytes, carrying
#: exactly one anchor (`synthetic://tsa/exp-1`).
LEGACY_TRUST_LIST_DIGESTS = {
    "8f04f3b64cf187aeda6c5896698e2dbd5f091002da957b3d323ee2ead9453c53":
        "INTEROP/oob/witness_trust_list.json (FROZEN, 530 B, 1 anchor) — "
        "pre-dates WIT-002 and cannot be amended; recognised by digest",
}

#: `WIT-001` v3 limb 1's outcomes, as an INSTRUMENT rather than as the claim the
#: clause makes. See `continuity_report`.
CONTINUITY_CONTINUOUS = "ordinals-non-decreasing"
CONTINUITY_DECREASED = "ordinal-decreased-within-era"
CONTINUITY_ERA_CROSSED = "stream-crosses-eras"
CONTINUITY_REPEATED = "ordinal-repeated-within-era"


def continuity_report(stream) -> dict:
    """What a countersignature stream's `ledger_ordinal` sequence ACTUALLY shows.

    `stream` is an ordered sequence of `(ledger_ordinal, era)` pairs, oldest
    first — the ordinals inside the bytes a witness countersigned.

    ⚠ **THIS DELIBERATELY DOES NOT DO WHAT `WIT-001` v3 LIMB 1 ASKS.**

    Limb 1 says *"a stream containing ordinals N and N+3 is itself the evidence
    that two checkpoints existed unobserved."* **Measured: false.**
    `CP-012` makes `ledger_ordinal` the **number of leaves** — the tree size —
    not a checkpoint sequence number, and `CP-017` requires only that it be
    **non-decreasing**. A ledger checkpointed at sizes 10, 25 and 60 produces
    gaps of 15 and 35, and every one of them is the ledger GROWING.

    **So a gap is not evidence of withholding, and an instrument that reported it
    as such would manufacture accusations out of ordinary operation** —
    `ERR-P3-008`'s own warning that a verdict of `ALTERED` is an accusation,
    one layer up.

    What a stream CAN tell a reader, and what this returns:

      * `decreased` — an ordinal went BACKWARDS within an era. That violates
        `CP-017` and is a real finding.
      * `repeated` — the same ordinal twice within an era. Legal if the heads
        match (`CP-017` permits non-decreasing, so equal is allowed) and
        `equivocation` if they do not — which `detect_equivocation` answers, not
        this function.
      * `era_crossed` — ⚠ the stream crosses an era boundary, and **every
        continuity claim stops at that line**. `CP-017` scopes monotonicity
        *within an era and construction*; `detect_equivocation` returns `None`
        across eras BY DESIGN. Measured: an era boundary defeats
        continuity, cadence and equivocation simultaneously, and `era` is a field
        the OPERATOR chooses and signs.
      * `gaps` — reported as a FACT with no verdict attached, because the reader
        may know the expected cadence and this function does not.
    """
    pairs = [(int(o), e) for o, e in stream]
    findings: list[str] = []
    gaps: list[tuple[int, int]] = []
    eras = [e for _, e in pairs]
    if len(set(eras)) > 1:
        findings.append(CONTINUITY_ERA_CROSSED)
    for (o1, e1), (o2, e2) in zip(pairs, pairs[1:]):
        if e1 != e2:
            continue                      # no continuity obligation crosses an era
        if o2 < o1:
            findings.append(CONTINUITY_DECREASED)
        elif o2 == o1:
            findings.append(CONTINUITY_REPEATED)
        elif o2 > o1 + 1:
            gaps.append((o1, o2))
    if not findings:
        findings.append(CONTINUITY_CONTINUOUS)
    return {
        "findings": sorted(set(findings)),
        "gaps": gaps,
        "gap_note": ("gaps are leaf-count growth, not missing checkpoints "
                     "(CP-012); they are reported as fact and carry no verdict"),
        "era_scoped": len(set(eras)) > 1,
    }


#: `WIT-001` v4 limb 1's outcomes — pairwise `CP-019` consistency over a stream.
CONSISTENCY_VERIFIED = "pair-consistent"
CONSISTENCY_FAILED = "pair-inconsistent"
CONSISTENCY_ERA_BOUNDARY = "pair-crosses-era-WIT-GAP-1"
CONSISTENCY_PROOF_ABSENT = "pair-proof-not-supplied"
#: The specification's v0.6 §1 limb 1 names TWO states — the proof is
#: published, or a `proof-withheld` entry is attested in the witness's own signed
#: record. **Measured: the instrument sees THREE.** A pair can
#: also arrive with no proof and no attested marker, which is what a stripped
#: proof and a lost transport both look like. The two are not the same evidence
#: and must not share one name: an attested withholding is an act the witness
#: signed for, an unattested absence is nobody's act on the record.
CONSISTENCY_PROOF_WITHHELD = "pair-proof-withheld-attested"
#: `head_construction_id` and `checkpoint_version` are in the
#: stream, GOVERN whether running the check means anything, and are NOT arguments
#: to `verify_consistency` — measured by introspecting its real signature, which
#: takes five parameters and neither of these. An earlier instrument gated on `era`
#: alone while `checkpoint.py`'s equivocation detector, in this same package,
#: already gated on era AND construction (`CP-017` says "same era and
#: construction"). The gap was mine, not the specification's.
CONSISTENCY_CONSTRUCTION_DIFFERS = "pair-crosses-construction"
CONSISTENCY_CONSTRUCTION_UNKNOWN = "pair-construction-unrecognised"
CONSISTENCY_VERSION_DIFFERS = "pair-crosses-checkpoint-version"


def _observation(item) -> dict:
    """Accept the 4-tuple or the published-proof mapping.

    The 4-tuple `(ledger_ordinal, head_hash, era, proof)` is carried unchanged so
    every vector keeps running as written — it states no construction and
    no version, and the gates that need them report that they had nothing to
    consult rather than passing silently.
    """
    if isinstance(item, Mapping) and "statement" in item and "proof_status" in item:
        # A `WIT-005` entry, the DECLARED carrier. The six `CP-011` fields
        # live under `statement`; the proof is carried when and only when
        # `proof_status == "verified"`, and `withheld` is the ATTESTED absence
        # this function has reported by name since.
        st = item["statement"]
        status = item["proof_status"]
        return {"ordinal": int(st["ledger_ordinal"]),
                "head": st["head_hash"],
                "era": st.get("era"),
                "proof": item.get("consistency_proof"),
                "construction": st.get("head_construction_id"),
                "version": st.get("checkpoint_version"),
                "withheld": status == "withheld"}
    if isinstance(item, Mapping):
        return {"ordinal": int(item["ledger_ordinal"]),
                "head": item["head_hash"],
                "era": item.get("era"),
                "proof": item.get("proof"),
                "construction": item.get("head_construction_id"),
                "version": item.get("checkpoint_version"),
                "withheld": bool(item.get("proof_withheld_attested", False))}
    ordinal, head, era, proof = item
    return {"ordinal": int(ordinal), "head": head, "era": era, "proof": proof,
            "construction": None, "version": None, "withheld": False}


def consistency_over_stream(stream, verify=None, constructions=None) -> list[dict]:
    """Re-run `CP-019` for each successively observed pair.

    `stream` is ordered oldest-first. Each item is either

      * the tuple `(ledger_ordinal, head_hash_bytes, era, proof_or_None)`, or
      * the **published-proof mapping** with the `CP-011` field names —
        `ledger_ordinal`, `head_hash`, `era`, `head_construction_id`,
        `checkpoint_version` — plus `proof` and `proof_withheld_attested`, or
      * the **`WIT-005` entry** — the declared carrier, recognised by
        carrying both `statement` and `proof_status`. The three forms are told
        apart by SHAPE and never by a flag a caller passes.

    ## What a measurement found, and what `v0.6` repaired

    `WIT-001` v4 limb 1 promised *"Any reader re-runs the same verification from
    the stream."* **A measurement found that false**: `CP-019` needs a proof, and
    `CP-011`'s body is a CLOSED SIX-FIELD set — `checkpoint_version`,
    `ledger_ordinal`, `head_hash`, `head_construction_id`, `era`, `kernel_time` —
    which does not contain one. `v0.6` §1 limb 1 repairs it by PUBLISHING the
    proof beside the countersigned statement.

    **The repair was re-measured against `verify_consistency`'s real signature,
    introspected rather than read: five parameters, `old_size`, `new_size`,
    `old_root`, `new_root`, `proof`. Every one is now sourced from the stream —
    the two sizes from `ledger_ordinal` (`CP-012`: the ordinal IS the tree size),
    the two roots from `head_hash`, and the proof from `v0.6`'s repair. ZERO
    arguments remain unsourced. The stream is argument-sufficient, and a proof is
    self-verifying whoever supplied it — a measurement proved that by handing the
    same bytes over from a hostile provenance and watching them verify, with four
    mutations refused and a wrong-root control refused.**

    ⚠ **BUT ARGUMENT-SUFFICIENCY IS NOT CHECK-SUFFICIENCY, AND THAT GAP WAS IN
    THIS FUNCTION.** Two of the six fields — `head_construction_id` and
    `checkpoint_version` — decide whether running the walk MEANS anything, and
    neither is a parameter, so nothing forces a caller to consult them.
    The earlier version consulted neither. They are gated below.

    ## The outcomes, and why none of them is silence

    - `pair-consistent` / `pair-inconsistent` — the walk ran and answered.
    - `pair-crosses-era-WIT-GAP-1` — neither verified nor failed. `CP-017` scopes
      monotonicity within an era and nothing binds era N's final state to era
      N+1's first. **Calling such a pair inconsistent would accuse an operator of
      a rewrite on the strength of an unruled boundary.**
    - `pair-crosses-construction` / `pair-construction-unrecognised` — `CP-015`
      carries the construction as DATA and `CP-003` says an unrecognised value is
      a STOP and never a fallback. This verifier walks RFC 6962; it must not walk
      it against a statement that names something else.
    - `pair-crosses-checkpoint-version` — `CP-011`: a change to any field's
      MEANING is a new `checkpoint_version`. Across a version boundary two
      `ledger_ordinal` values need not denote the same quantity.
    - `pair-proof-withheld-attested` — `v0.6`'s recorded refusal: the witness
      signed for the fact that it asked and was refused.
    - `pair-proof-not-supplied` — no proof AND no attested marker. **Kept
      separate from the line above on purpose**: a stripped proof
      and a dropped packet both land here, and neither is an act anyone signed
      for.

    ⚠ **A measurement showed what the marks are worth and the answer is not
    flattering: exactly ONE pair is marked per rewrite, and raising the witness's
    cadence from 3 pairs to 29 did not raise that count above one.** The mark is
    real, it localises the rewrite to one interval, and it does not grow with the
    crime. What it costs the operator is stated; what it does not
    cost them is stated there too.

    `constructions` defaults to `merkle.CONSTRUCTIONS` and is a parameter only so
    a vector can substitute one — the identifier is never hard-coded here
    (`CP-015`: "no call site may hard-code it").
    """
    if verify is None:                      # imported here so a test can substitute one
        from .merkle import verify_consistency as verify
    if constructions is None:
        from .merkle import CONSTRUCTIONS as constructions
    out: list[dict] = []
    items = [_observation(i) for i in stream]
    for a, b in zip(items, items[1:]):
        pair = {"from": a["ordinal"], "to": b["ordinal"],
                "era_from": a["era"], "era_to": b["era"],
                "construction_from": a["construction"],
                "construction_to": b["construction"]}
        if a["era"] != b["era"]:
            pair["outcome"] = CONSISTENCY_ERA_BOUNDARY
            pair["detail"] = ("grade-(b) evidence does not carry across an era "
                              "boundary; WIT-GAP-1 is unruled")
        elif a["construction"] != b["construction"]:
            pair["outcome"] = CONSISTENCY_CONSTRUCTION_DIFFERS
            pair["detail"] = (f"the pair names {a['construction']!r} then "
                              f"{b['construction']!r}; CP-015 carries the "
                              "construction as data and two constructions are "
                              "two trees, not one history")
        elif a["construction"] is not None and a["construction"] not in constructions:
            pair["outcome"] = CONSISTENCY_CONSTRUCTION_UNKNOWN
            pair["detail"] = (f"CP-003: unrecognised head_construction_id "
                              f"{a['construction']!r} — stopping. This verifier "
                              "walks RFC 6962 and will not fall back to it for a "
                              "statement naming something else")
        elif a["version"] != b["version"]:
            pair["outcome"] = CONSISTENCY_VERSION_DIFFERS
            pair["detail"] = (f"the pair names checkpoint_version {a['version']!r} "
                              f"then {b['version']!r}; CP-011 makes a new version "
                              "the vehicle for a changed field MEANING, so the two "
                              "ledger_ordinal values need not denote one quantity")
        elif b["proof"] is None and b["withheld"]:
            pair["outcome"] = CONSISTENCY_PROOF_WITHHELD
            pair["detail"] = ("the witness attested that it asked for the CP-019 "
                              "proof and was refused; the chain is SEVERED here "
                              "and no continuity claim spans this pair")
        elif b["proof"] is None:
            pair["outcome"] = CONSISTENCY_PROOF_ABSENT
            pair["detail"] = ("no proof and no attested withholding: a stripped "
                              "proof and a lost transport are indistinguishable "
                              "here, and neither is an act anyone signed for. Nor "
                              "can a reader repair it: CP-011's body is six closed "
                              "fields and a proof is not one of them, and "
                              "reconstructing one needs the leaves between the two "
                              "sizes")
        else:
            try:
                verify(old_size=a["ordinal"], old_root=a["head"],
                       new_size=b["ordinal"], new_root=b["head"], proof=b["proof"])
                pair["outcome"] = CONSISTENCY_VERIFIED
            except Exception as exc:
                pair["outcome"] = CONSISTENCY_FAILED
                pair["detail"] = str(exc)
        out.append(pair)
    return out


#: Refusal codes for the custody record.
CUSTODY_REFUSALS = (
    "witness-custody-record-absent",
    "witness-independence-unrecognised",
    "witness-independence-inconsistent",
    "witness-observation-grade-unrecognised",
)


def custody_problems(anchor: "Anchor", *, legacy: bool = False) -> list[str]:
    """Every problem with `anchor`'s custody record. Empty means it holds.

    `legacy` is passed by a caller that has recognised the anchor's SOURCE in
    `LEGACY_TRUST_LIST_DIGESTS` — it is a fact about the artefact, never about
    the anchor, so it is supplied rather than inferred (`GUARD-001`: a check a
    test can disable is a check a test can prove fires).
    """
    problems: list[str] = []
    declared = (anchor.custodian is not None
                or anchor.operator_recoverable is not None
                or anchor.independence is not None)
    if not declared:
        if not legacy:
            problems.append("witness-custody-record-absent")
        return problems

    if anchor.independence is not None and anchor.independence not in INDEPENDENCE_VALUES:
        problems.append("witness-independence-unrecognised")

    # ⚠ The inconsistency refusal. `independence` is DERIVABLE from
    # `operator_recoverable`, so a declaration that contradicts its own grounds
    # is refused rather than believed: an operator-recoverable key is not
    # independent, whatever the label beside it says.
    if anchor.operator_recoverable is True and anchor.independence == INDEPENDENT:
        problems.append("witness-independence-inconsistent")
    if anchor.operator_recoverable is False and anchor.independence == OPERATOR_HELD:
        problems.append("witness-independence-inconsistent")
    if (anchor.observation_grade is not None
            and anchor.observation_grade not in OBSERVATION_GRADES):
        problems.append("witness-observation-grade-unrecognised")
    return problems


class WitnessTrustList:
    """A provisioned mapping from `witness_key_ref` to `Anchor`.

    **There is no default and no discovery.** An empty trust list is a
    legitimate, explicit state — a verifier that anchors nobody — and it is not
    the same as no trust list at all, which is a verifier that was never
    provisioned. The two produce different reason codes because they are
    different facts about the VERIFIER, and `ERR-P3-008`'s whole discipline is
    that the reason a check did not pass is part of the answer.
    """

    def __init__(self, anchors: Mapping[str, Anchor]) -> None:
        for ref, anchor in anchors.items():
            if not isinstance(anchor, Anchor):
                raise TypeError(f"{ref!r} is not an Anchor")
            if anchor.witness_key_ref != ref:
                raise ValueError(
                    f"anchor keyed {ref!r} carries witness_key_ref "
                    f"{anchor.witness_key_ref!r}; a trust list that disagrees with "
                    "itself cannot anchor anything")
        self._anchors = dict(anchors)

    def anchor_for(self, witness_key_ref: str) -> Anchor | None:
        return self._anchors.get(witness_key_ref)

    def __len__(self) -> int:
        return len(self._anchors)


def agreement_finding(anchor: Anchor, bundle_key_material: bytes | None,
                      bundle_format: str | None, *, limits=None) -> str | None:
    """`BV-011` **as CORRECTED: it compares KEYS, not ENCODINGS.**

    Returns a NAMED FINDING, or `None` when the two sides denote the same key.

    **This is the only function in this module that sees the bundle's copy, and
    all it can produce is a sentence.** It cannot return a key, so nothing it
    touches can reach a signature check; it cannot return an outcome, so nothing
    it finds can move a verdict.

    ## ⚠ What changed, and why the old test was wrong

    The first interoperation run reported the bundle's key material as differing
    from the anchor's **when they were the same key** — a certificate on one
    side, the raw 32 bytes it embeds on the other. `BV-009` makes `format`
    *"how to interpret `key_material`"*, ***which is precisely the case in which
    equality of bytes is the wrong test.***

    **Both sides are reduced, under their DECLARED formats, to the key they
    denote, and compared then. A difference in `format` alone is not a
    difference in key** — and where the keys agree this returns `None`, because
    `BV-011` reports DISAGREEMENT and two representations of one key are not one.

    ## ⚠ And where a side will not reduce, the answer is `NOT COMPARED`

    **Never a difference** — `BV-013`'s discipline, and `BV-028` at the key
    layer. *A verifier that reports its own inability to decode a representation
    as a disagreement between two parties has manufactured a finding against the
    exporter out of a gap in itself.* The finding says WHICH SIDE did not reduce
    and WHAT STOPPED IT, so a reader can tell the verifier's gap from the
    material's defect.

    `limits` is the provisioned `der.Limits` for reducing a representation that
    must be parsed (`BV-023`). **`None` means this verifier was not provisioned
    to parse one**, which is its own named cause and is still `NOT COMPARED`.
    """
    if bundle_key_material is None:
        return (f"the bundle carries no witness_keys entry for "
                f"{anchor.witness_key_ref!r}; verification used the anchor, as it "
                "would have regardless")

    reduced = {}
    for side, material, fmt in (("anchor", anchor.key_material, anchor.format),
                                ("bundle", bundle_key_material, bundle_format)):
        try:
            reduced[side] = key_forms.reduce_to_ed25519(material, fmt, limits=limits)
        except key_forms.KeyFormError as exc:
            return (f"BV-011 NOT COMPARED, and NOT thereby agreed: the {side}'s key "
                    f"material for {anchor.witness_key_ref!r} declares format "
                    f"{fmt!r} and this verifier did not reduce it to the key it "
                    f"denotes ({exc.code}: {exc.detail}). Verification used the "
                    "ANCHOR either way. This states an absence of "
                    "comparison and is not a disagreement between the two sides")

    if reduced["anchor"] != reduced["bundle"]:
        return (f"BV-011: the bundle's key material for {anchor.witness_key_ref!r} "
                f"denotes a DIFFERENT KEY from the anchor's — compared after both "
                f"were reduced under their declared formats "
                f"({bundle_format!r} and {anchor.format!r}), so this is a key "
                "difference and not a representation difference. Verification used "
                "the ANCHOR. This is a finding against the exporter and is not "
                "evidence about the record: it neither lowers nor raises the verdict")
    return None


def verify_token(anchor: Anchor, *, witness_kind: str, token: bytes,
                 attested_digest: bytes,
                 token_verifiers: Mapping[str, TokenVerifier]) -> tuple[str, str]:
    """Verify one opaque witness token under an ANCHORED key.

    Returns `(result, reason)` where `result` is one of `RESULTS` and the head
    of `reason` is one of `REASONS`.

    **⚠ THE FIRST VALUE WAS ONCE A `bool`.** A bool could carry
    *verified* against *not verified* and nothing else, so the two epistemically
    opposite refusals — the token failed, and this build could not try — arrived
    at the caller indistinguishable and landed together on `REFUTED`. That was
    the defect, and `BV-028`'s operational boundary is the ruling on it: **the class
    of a refusal is part of the contract, and the contract is part of the
    specification** (`BV-024`).

    **There is no parameter here through which a bundle-supplied key could
    arrive.** `BV-010` is enforced by the shape of this call rather than by the
    discipline of its callers — *a rule a caller must remember is a rule that
    holds until the next caller.*

    ## ⚠ The findings channel, and why it cannot move a verdict

    A checker may report **things it LEARNED** — an RFC 3161 `genTime`, a serial,
    a policy — by returning `(verified, findings)`. **They are appended to the
    reason AFTER `REASON_SEPARATOR`, and the outcome is decided by `verified`
    alone.**

    > ***The verdict is a function of the RESULT. The findings are a function
    > of nothing.*** A caller branches on `result`, a closed vocabulary that no
    > finding can reach, and never on the reason's text. *`reason_code` remains
    > available to a READER; it is no longer the dispatch channel, because a
    > dispatch that parses a string one finding away from attacker text is a
    > dispatch waiting to be moved.*
    >
    > **This matters because part of a finding's text comes from the token,
    > which is attacker-supplied.** *A channel that reports what an attacker
    > wrote must not be a channel that decides anything.*
    """
    checker = token_verifiers.get(witness_kind)
    if checker is None:
        # H-8. ERR-P3-005 makes the token the witness's own artefact; checking
        # it means implementing that witness's format. Absence of a checker is
        # absence of evidence, never evidence of failure.
        #
        # ⚠ Deliberately carries NO findings, and that is load-bearing: no
        # checker ran, so there is nothing to report.
        return NO_CHECKER, "witness-kind-not-implemented"
    outcome, findings = _normalise(
        checker(anchor.key_material, anchor.format, token, attested_digest))
    if outcome == TOKEN_VERIFIED:
        return TOKEN_VERIFIED, _with_findings("witness-anchored-and-verified",
                                              findings)
    if outcome == TOKEN_REFUSED_TOKEN_DEFECT:
        # ERR-P3-008: evidence supplied, and it failed.
        return outcome, _with_findings("witness-token-does-not-verify", findings)
    if outcome == TOKEN_REFUSED_CHECKER_SHORT:
        # BV-020's FIFTH FACT. The witness is anchored, a checker for its kind
        # was provisioned, IT EXECUTED, and it holds no implementation for
        # something the token or the anchor declares. The operator has climbed
        # every step and still gets nothing, and a verdict that cannot say so
        # sends them to solve the wrong problem.
        return outcome, _with_findings("witness-checker-cannot-evaluate", findings)
    # BV-020's self-repairing clause. A fact no member of the closed set names,
    # reported AS a specification finding and not absorbed into REFUTED.
    return REFUSAL_CLASS_ABSENT, _with_findings(
        "witness-checker-refusal-class-absent", (SPECIFICATION_FINDING,) + findings)
