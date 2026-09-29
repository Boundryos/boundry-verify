"""`BV-025` — a signature is carried AS IT WAS MADE, and the form is NAMED.

**. This module did not exist and the clause it implements is why the
 run reached no verdict.** The verifier read `record.cose_sign1` and
`checkpoint.cose_sign1`, which is **as it stood
before **. The current text carries `signature` and `signature_form` on
both objects, and `cose_sign1` on neither.

## What the specification says, and it is a correction of a ruling

> **`D1` is the fact on the ground: a sealed record's signature is raw Ed25519
> over `canonical_serialise(payload)`.** A COSE_Sign1 signature is over a
> `Sig_structure` — `["Signature1", protected, external_aad, payload]` — never
> over the payload alone, **therefore an existing signature is not a COSE
> signature and cannot be re-labelled as one.**

**So the container names the construction rather than assuming it**, and
`ed25519-canonical-v1` is the name for everything sealed under `D1`.
**An unrecognised `signature_form` STOPS verification** — `BV-025` and section
12 steps 2 and 5 both say so, in those words. *This is `head_construction_id`'s
discipline applied to signatures, for the same reason: no fallback to an assumed
construction, ever.*

## ⚠ The recognised set is PROVISIONED, and that is `BV-004` and not a choice

`BV-004` was **extended ***"the no-default discipline covers EVERY
named profile identifier in a bundle, `record.form_tag` included."*
`signature_form` is a named profile identifier that arrived after that
extension was written, and it inherits the rule — a verifier that defaults it
has certified its own guess about which construction produced the bytes it is
about to check.

**Being IMPLEMENTED here and being PROVISIONED by an operator are two facts and
they are kept apart**, because they fail for different reasons and send an
operator to different fixes:

| state | code |
|---|---|
| the caller passed no set at all | `signature-forms-not-provisioned` |
| this build performs no such construction — **provisioned or not** | `signature-form-not-implemented` |
| this build performs it, and the operator did not provision it | `signature-form-not-recognised` |

⚠ **The middle row said "provisioned, and this build performs no such
construction" until.** *That word was narrower than the code directly
beneath it: `resolve` checks `CONSTRUCTIONS` membership BEFORE provisioned-set
membership, so an unimplemented name never reaches the provisioning question and
the reason fires whether or not the set contains it.* ** across
four provisioned sets including the empty one, and the specification's gloss was
corrected first; this table is the
same defect in the file the ordering lives in, aligned.**

*Nothing about the behaviour changes here. The rows are read by people, and a
table that describes the code less exactly than the code describes itself is the
kind of documentation that survives precisely because nobody executes it.*

*`BV-020`'s discipline — each reason names a different fact about the verifier's
provisioning, and collapsing them hides which one to fix — applied one clause
along.*

## ⚠ What is NOT here, and why nothing was invented to fill it

**`D5-a` stands for signatures made in a future era** and `BV-016`/`BV-021`
describe the COSE profile that era will use. **This specification version names
no `signature_form` value for it.** `cose.py` implements that profile and is
reachable the moment a form identifier for it exists; **inventing one now would
be inventing the specification**, which is the failure stopped for.
"""

from __future__ import annotations

from typing import Callable, Mapping

from .ed25519 import verify as ed25519_verify

__all__ = ["SignatureFormError", "ED25519_CANONICAL_V1",
           "THIS_ERA_SIGNATURE_FORM", "CONSTRUCTIONS", "REFUSALS", "resolve"]

#: `BV-025`, named in the specification's own words: *"`ed25519-canonical-v1`
#: for everything sealed under `D1`."*
ED25519_CANONICAL_V1 = "ed25519-canonical-v1"

#: ⚠ **NOT a default.** Exactly the status of `bundle.THIS_VERSION_ENCODING_ID`:
#: a constant that exists to be *provisioned* by a caller who has decided to
#: accept this construction, never to be silently assumed.
THIS_ERA_SIGNATURE_FORM = ED25519_CANONICAL_V1

REFUSALS = (
    "signature-forms-not-provisioned",
    "signature-form-not-implemented",
    "signature-form-not-recognised",
)


class SignatureFormError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def _ed25519_canonical_v1(public_key: bytes, message: bytes,
                          signature: bytes) -> bool:
    """Raw Ed25519 over the canonical bytes themselves — no wrapper, no context.

    **The message is the bytes the object already carries**: `canonical_bytes`
    for a record, and the canonical bytes RE-EMITTED from `statement` for a
    checkpoint (`BV-015`). *There is no `Sig_structure` here and that absence is
    the clause: an array wrapper would make this a COSE signature, which is
    precisely what `BV-025` establishes these are not.*

    `ERR-P3-006` names the variant: RFC 8032 section 5.1.7 verification with the
    cofactorless equation, which is what `ed25519.verify` implements.
    """
    return ed25519_verify(public_key, message, signature)


#: What this build can actually perform. **Membership here is not permission** —
#: `resolve` requires the operator's provisioned set as well.
CONSTRUCTIONS: Mapping[str, Callable[[bytes, bytes, bytes], bool]] = {
    ED25519_CANONICAL_V1: _ed25519_canonical_v1,
}


def resolve(signature_form: str, *,
            recognised_signature_forms: frozenset | None):
    """Return the verifying callable for `signature_form`, or STOP.

    `recognised_signature_forms` is a **provisioned input with no default**
    (`BV-004` as extended). `None` means *this verifier was never provisioned*,
    which is a different fact from an empty set — *a verifier that recognises no
    signature form at all* — and the two produce different reason codes.

    ⚠ **Resolved at CALL time and read from the module, never bound as a
    parameter default.** A default argument is bound when the function is
    DEFINED, so a mutation of `CONSTRUCTIONS` would never reach the lookup and
    would read `INERT` — `M12`'s dead-knob defect, which this programme has now
    found in three files. *A constant a test can change must be read where it is
    used.*
    """
    if recognised_signature_forms is None:
        raise SignatureFormError(
            "signature-forms-not-provisioned",
            "this verifier was not told which signature constructions it may "
            "accept, so it cannot check a signature at all. An "
            "unrecognised signature_form STOPS verification, and no set is not "
            "the same fact as an empty set")
    if signature_form not in CONSTRUCTIONS:
        raise SignatureFormError(
            "signature-form-not-implemented",
            f"{signature_form!r} names a construction this build does not "
            "perform; stopping rather than checking the bytes under a "
            "construction that was not the one they were made under")
    if signature_form not in recognised_signature_forms:
        raise SignatureFormError(
            "signature-form-not-recognised",
            f"{signature_form!r} is not among the signature forms this verifier "
            f"was provisioned to accept "
            f"({sorted(recognised_signature_forms) or 'none'}); this build "
            "performs it and the operator has not authorised it")
    return CONSTRUCTIONS[signature_form]
