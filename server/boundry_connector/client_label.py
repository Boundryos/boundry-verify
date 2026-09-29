"""The client label convention — minted, enforced, and never derived.

⚠ **THIS MODULE LIVES IN THE SHIPPED PACKAGE ON PURPOSE.** It was first placed
in `REGISTERS/`, and `test_every_module_imports_clean_in_a_fresh_interpreter`
refused it within the minute: the connector is handed to the operator as a
folder that runs on stdlib alone, and a cross-tree import breaks
that property. **The convention travels with the artefact that ships it**, and
the bridge — which never ships — imports it from here rather than restating it
(a boundary is imported, never retyped).

The convention itself is specified in `11_ROADMAP_PROGRAMME/SPECS/`.
The operator's decision of 2 September 2026 fixes the prefix `B-`.

⚠ **NO REAL CLIENT LABEL IS MINTED IN CANON AND NO CLIENT DATA ENTERS IT.**
Everything this module is exercised with is synthetic.

⚠ **THE MAPPING NEVER LIVES HERE.** Spec §7: label-to-client sits on the MyFDC
client record and nowhere else. This module mints and validates STRINGS. It has
no client argument, no client field, and no place to put one — which is the
point, and measures the abstention rather than promising it.

⚠ **K-3.** Import is definitions only: no I/O, no clock, no network.
"""

from __future__ import annotations

from boundry_connector.refusal import Refusal

import secrets
from typing import NewType

__all__ = ["DEPLOYMENT_CHECK_SYMBOLS", "CHECK_DECISION",
           "ALPHABET", "CHECK_ALPHABET", "PREFIX", "CODE_LENGTH",
           "deployment_validate",
           "LabelRefused", "CHECK_BLIND_SET", "mint", "mint_synthetic",
           "check_symbol", "validate", "render", "is_valid", "is_reserved",
           "RESERVED_POSITION", "RESERVED_SYMBOL", "LEGACY_SYNTHETIC",
           "ClientLabel"]

#: Crockford base32. I, L, O and U are absent — the first three because they
#: confuse with 1 and 0, the fourth to avoid accidental words.
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

#: ⚠ **THE DEPLOYMENT PROPERTY, DECIDED BY THE OPERATOR ON 3 SEPTEMBER 2026.**
#: `SPEC v0.2` §1 made check-symbol use a property of the DEPLOYMENT rather
#: than of the convention, and left it unchosen. It is chosen: **OFF.**
#:
#: Carried as DATA and not as a default argument, because a default is
#: something every caller may override without noticing and a deployment
#: property is not. `deployment_validate()` reads this; nobody passes it.
DEPLOYMENT_CHECK_SYMBOLS = False

#: ⚠ **AND IT IS NOT FREELY REVERSIBLE — the part the operator was told, kept
#: where the decision is.** Carried as a tuple so the vocabulary sweep governs
#: it and a later seat cannot quietly soften the wording.
CHECK_DECISION: tuple[str, ...] = (
    "OFF for this deployment. Operator's decision of 3 September 2026, "
    "recorded at R-180 §1 and ordered into the convention at WO-CX-20 V61",
    "NOT FREELY REVERSIBLE. A check symbol changes the label's LENGTH, and the "
    "fixed length is what keeps the `B-` prefix unambiguous once separators "
    "are stripped (§4). `B` is itself a Crockford character, so the prefix "
    "boundary is recoverable only because the stripped form is exactly 6",
    "turning checks ON later gives labels minted after that date a different "
    "stripped length from every label minted before it, and a deployment "
    "holding two lengths has NO unambiguous prefix rule at all — not a "
    "degraded one, none",
    "so the reversal is not a setting change: it is a re-issue of every label "
    "already minted, against a MyFDC record this programme does not write",
)

#: Crockford's five extended symbols, used ONLY for the check character.
CHECK_ALPHABET = ALPHABET + "*~$=U"

#: ⚠ **THE DECLARED TYPE, AND WHY IT IS A `NewType` AND NOT A SUBCLASS.**
#:
#: /. Three times this programme has met one shape — the
#: boundary list, key material, acceptors at
#: — and each time **recognition was bounded by whether the thing
#: happened to be NAMED like itself.** Twice the repair was a DECLARATION. This
#: is the third.
#:
#: ***It does NOT subclass `str`.*** A measurement showed what subclassing a
#: built-in costs: a `frozenset` subclass was silent for `reach & VALIDATORS`
#: because `set.__and__` accepts any set INSTANCE and never defers. A `NewType`
#: is erased at runtime — it IS a `str` — and what the sweep reads is the
#: ANNOTATION on the tree, never the runtime class.
ClientLabel = NewType("ClientLabel", str)

PREFIX = "B-"

#: ⚠ **THE RESERVED SYNTHETIC SUBSPACE**. One fixed value in
#: ONE code position. **It is not an entity type and §5 is untouched** — it
#: carries no information about the client, only about whether the label was
#: ever issuable at all.
#:
#: ***Canon cannot collide with a real label by CONSTRUCTION rather than by
#: CARE.*** The operator's mint refuses to draw from here; canon's vectors mint
#: only from here. Before this, four synthetic labels sat in canon because
#: someone chose them carefully, and one of them arrived inside the sentence
#: explaining 's Defect 2.
RESERVED_POSITION = 0
RESERVED_SYMBOL = "Z"

#: ⚠ The four synthetic labels ALREADY IN CANON, recorded BY VALUE and never
#: issuable by either path. **The documents carrying them are not rewritten** —
#: canon does not edit a filed record, so the record carries the values instead.
LEGACY_SYNTHETIC: tuple[str, ...] = (
    "B-K7M-4QT",   # the vectors' standing label
    "B-9RT-2WX",   # the mismatch vector's second label
    "B-XXX-XXX",   # the spec's own form template
    "B-17M-4QT",   # arrived inside 's explanation of Defect 2
)

#: ⚠ **SPEC §4 IS LOAD-BEARING AND THIS IS WHY IT IS A CONSTANT.** `B` is itself
#: a Crockford character, so a label stripped of separators — `BK7M4QT` — is
#: only parseable because the code length is fixed. A variable length makes the
#: prefix boundary unrecoverable in every filename, URL and pasted cell.
CODE_LENGTH = 6


class LabelRefused(Refusal):
    """⚠ A malformed label is REFUSED NAMING THE CLAUSE IT FAILED — never
    coerced, never silently normalised."""

    def __init__(self, clause: str, detail: str) -> None:
        self.clause = clause
        self.detail = detail
        super().__init__(f"{clause}: {detail}")


def _value(code: str) -> int:
    n = 0
    for ch in code:
        n = n * len(ALPHABET) + ALPHABET.index(ch)
    return n


def check_symbol(code: str) -> str:
    """Crockford's check symbol: the code's value modulo 37."""
    return CHECK_ALPHABET[_value(code) % 37]


#: ⚠ **THE CHECK SYMBOL'S DECLARED BLIND SET** — every detector
#: states what it cannot see. Filled in from the exhaustive measurement at
#: It is held by a vector, not by the algorithm's reputation.
CHECK_BLIND_SET: tuple[str, ...] = (
    "any error that leaves the code's value unchanged modulo 37 — a single "
    "character substitution is always caught, but a compensating pair of "
    "errors is not",
    "an error in the check symbol itself is indistinguishable from an error in "
    "the code: the checker reports a mismatch and cannot say which side moved",
    "a label that is well-formed and simply belongs to a different client — a "
    "check symbol detects typing damage, never wrongness",
)


def is_reserved(label: str) -> bool:
    """Is this label from the synthetic subspace, or a recorded legacy value?"""
    if label in LEGACY_SYNTHETIC:
        return True
    try:
        code = validate(label).removeprefix(PREFIX).replace("-", "")
    except LabelRefused:
        try:
            code = validate(label, with_check=True).removeprefix(PREFIX).replace("-", "")[:CODE_LENGTH]
        except LabelRefused:
            return False
    return code[RESERVED_POSITION] == RESERVED_SYMBOL


def mint_synthetic(*, issued: frozenset[str], with_check: bool = False,
                   _attempts: int = 64) -> str:
    """Mint a label FOR CANON. Always from the reserved subspace."""
    return _mint(issued=issued, with_check=with_check, _attempts=_attempts,
                 reserved=True)


def mint(*, issued, with_check: bool = False, _attempts: int = 64) -> str:
    """Mint an ISSUABLE label — never from the reserved subspace.

    ⚠ **`issued` HAS NO DEFAULT, AND THAT IS THE MECHANISM**.
    It previously defaulted to the empty set. A finding stated the limit
    honestly — uniqueness holds only if the caller's set is complete — and **an
    empty default turns a stated limit into a silent one**: a caller who simply
    forgot would get a label that had never been checked against anything, and
    nothing would say so.
    """
    if issued is None:
        raise LabelRefused(
            "§6 stable, and never reused",
            "the issued-and-retired set is required and was not given. The "
            "label-to-client field on the MyFDC client record is the SET OF "
            "RECORD; this function never goes looking for it and refuses "
            "rather than defaulting to empty, because an empty default would "
            "make an unchecked label indistinguishable from a checked one")
    return _mint(issued=frozenset(issued), with_check=with_check,
                 _attempts=_attempts, reserved=False)


def _mint(*, issued: frozenset[str], with_check: bool, _attempts: int,
          reserved: bool) -> str:
    """Mint one label. **`secrets`, never `random`** (spec §3).

    ⚠ **`issued` IS NOT OPTIONAL IN PRACTICE AND MEASURED WHY.** The
    draft specified no uniqueness mechanism at all while §6 promises a label
    holds for life and is never reissued. Over a 32^6 space the birthday bound
    gives **P(collision) ≈ 4.5% at 10,000 labels and 0.69 at 50,000** — not a
    theoretical risk for a practice, and a collision breaks §6 outright.
    Pass every label ever issued OR RETIRED; a retired label is never reissued
    because bundles already handed out still carry it.

    ⚠ **NO MODULO BIAS, AND NOT BECAUSE 32 DIVIDES 256.** `secrets.choice` uses
    `randbelow`, which rejects out-of-range draws rather than folding them, so
    the draw is uniform for ANY alphabet size. *Relying on 32 | 256 would make
    the property an accident of this alphabet; it is a property of the method.*
    """
    # ⚠ **ONLY THE RESERVED POSITION IS CONSTRAINED.** A draft excluded the
    # reserved symbol at EVERY position, which silently shrank the space from
    # 32^6 to 31^6 and would have made `Z` unreachable in five positions that
    # have nothing to do with the subspace — a uniformity defect introduced by
    # the very change meant to keep canon and the operator apart.
    head = ALPHABET.replace(RESERVED_SYMBOL, "")
    for _ in range(_attempts):
        code = "".join(
            (RESERVED_SYMBOL if reserved else secrets.choice(head))
            if i == RESERVED_POSITION else secrets.choice(ALPHABET)
            for i in range(CODE_LENGTH))
        label = render(code, with_check=with_check)
        if label in LEGACY_SYNTHETIC or label in issued:
            continue
        if reserved != (code[RESERVED_POSITION] == RESERVED_SYMBOL):
            continue
        return label
    raise LabelRefused(
        "§6 stable, and never reused",
        f"could not mint an unused label in {_attempts} attempts against "
        f"{len(issued)} issued; the space is exhausted or the issued set is wrong")


def render(code: str, *, with_check: bool = False) -> str:
    """`B-XXX-XXX`, or `B-XXX-XXX-C` when the deployment uses check symbols.

    ⚠ **THE CHECK SYMBOL GETS ITS OWN GROUP, AND MEASURED WHY.** The
    draft appended it as an optional seventh character, which makes the stripped
    form 7 OR 8 characters — reintroducing exactly the prefix ambiguity §4
    exists to prevent. Its own group keeps the rendered form unambiguous, and
    the deployment declares whether checks are on so the stripped length is
    fixed WITHIN a deployment.
    """
    if len(code) != CODE_LENGTH or any(c not in ALPHABET for c in code):
        raise LabelRefused("§1 the form",
                           f"{code!r} is not {CODE_LENGTH} Crockford characters")
    out = f"{PREFIX}{code[:3]}-{code[3:]}"
    return f"{out}-{check_symbol(code)}" if with_check else out


def validate(label: str, *, with_check: bool = False) -> ClientLabel:
    """Return the canonical label, or refuse NAMING THE CLAUSE IT FAILED.

    ⚠ **TWO ALPHABETS, TWO POSITIONS, AND CONFLATING THEM WAS THE FLAKE.**
    The two CODE groups are governed by `ALPHABET` — Crockford base32, 32
    symbols, `I`/`L`/`O`/`U` excluded as confusable. The CHECK group is governed
    by `CHECK_ALPHABET` — Crockford's 37 check symbols, which legitimately
    INCLUDES `U` at value 36 — and by the `check_symbol()` comparison below.
    **A rule that belongs to one alphabet is never applied to the other's
    position of the check symbol**.

    ⚠ **CASE IS CANONICALISED; SYMBOLS ARE NEVER SUBSTITUTED.** Upper and lower
    case are the same Crockford symbol, so folding them changes nothing and is
    not the coercion forbids. **Crockford's decode ALSO maps `I`/`L`→`1`
    and `O`→`0`, and that is a different symbol** — accepting it would silently
    turn one client's label into another's. measured the substitution
    and this function refuses it.
    """
    if not isinstance(label, str) or not label:
        raise LabelRefused("§1 the form", "a label is a non-empty string")
    up = label.strip().upper()
    if not up.startswith(PREFIX):
        raise LabelRefused("§1 the form",
                           f"{label!r} does not carry the operator's `B-` prefix")
    parts = up[len(PREFIX):].split("-")
    expected = 3 if with_check else 2
    if len(parts) != expected:
        raise LabelRefused(
            "§1 the form",
            f"{label!r} has {len(parts)} group(s) after the prefix; this "
            f"deployment renders {expected}")
    code = parts[0] + parts[1]
    if len(parts[0]) != 3 or len(parts[1]) != 3:
        raise LabelRefused("§4 length is part of the convention",
                           f"{label!r} is not two groups of three; `B` is itself "
                           f"a Crockford character, so a variable length makes "
                           f"the prefix boundary unrecoverable")
    # ⚠ **THE `ILOU` SCAN GOVERNS THE CODE GROUPS ONLY** (executing
    # the operator's decision of 3 September). It ran over the WHOLE label and
    # refused a legitimate check symbol: `U` is Crockford's 37th check symbol,
    # value 36, and `CHECK_ALPHABET` holds it correctly — the scan was applying
    # the CODE alphabet's rule to a position that alphabet does not govern.
    # Measured before the change: 535 of 20,000 minted labels refused, 1 in
    # 37.4, every one with check symbol `U`, every one under this clause.
    for bad in "ILOU":
        if bad in code:
            raise LabelRefused(
                "§2 the alphabet",
                f"{bad!r} is not a Crockford character. Crockford's decode would "
                f"map it to another symbol and silently yield a DIFFERENT label; "
                f"this refuses instead of substituting")
    if any(c not in ALPHABET for c in code):
        raise LabelRefused("§2 the alphabet",
                           f"{label!r} carries a character outside Crockford base32")
    if with_check:
        if parts[2] != check_symbol(code):
            raise LabelRefused(
                "§1 the form",
                f"check symbol {parts[2]!r} does not match {check_symbol(code)!r}; "
                f"the checker cannot say which side moved")
    return ClientLabel(render(code, with_check=with_check))


def deployment_validate(label: str) -> ClientLabel:
    """Validate under THIS DEPLOYMENT'S declared check-symbol property.

    ⚠ **THE POINT OF THIS FUNCTION IS THAT IT TAKES NO `with_check`.** Every
    call site that passes the flag can pass the wrong one; a deployment
    property is read from the declaration or it is not a property. A label
    carrying a check symbol is REFUSED here, naming the clause it failed,
    because this deployment renders two groups and not three.
    """
    return validate(label, with_check=DEPLOYMENT_CHECK_SYMBOLS)


def is_valid(label: str, *, with_check: bool = False) -> bool:
    try:
        validate(label, with_check=with_check)
        return True
    except LabelRefused:
        return False
