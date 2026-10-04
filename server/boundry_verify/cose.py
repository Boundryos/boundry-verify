"""COSE_Sign1 verification — STOP-B.

**Built from RFC 9052 and `ERR-P3-006` alone.**
The kernel repository has not been read.

`BV-005` and `BV-006` put a `cose_sign1` byte string beside the bytes it signs,
for both the record and the checkpoint statement. Nothing in the programme
corpus specifies the COSE profile beyond *"COSE_Sign1"* and *"Ed25519 per
`ERR-P3-006`"*, so the decisions this module had to take are named in
`REFUSALS` and argued in the docstrings rather than buried.

## ⚠ The payload is DETACHED, and that is forced by `BV-008`

`BV-005` requires **both** `canonical_bytes` and `cose_sign1`. If the
COSE_Sign1 carried its payload attached, then `canonical_bytes` would be a
value *"a signed object inside it already determines"* — and `BV-008` says
plainly that **deriving it is mandatory and carrying it is a refusal.** The two
requirements cannot both hold with an attached payload.

**With a detached payload they are consistent**, so this module requires
`payload = nil` and refuses an attached one as `cose-payload-attached`.
This is an inference from two normative rules, not a reading of
one, and it is the kind of thing the exporter session will implement the other
way if it is not ruled.

## `alg` must be in the PROTECTED header — `BV-021`, NORMATIVE

RFC 9052 permits `alg` in either bucket. **`BV-021` requires it protected.**
An algorithm declaration in the unprotected bucket is not covered by the
signature, so a relaying party can rewrite it; a verifier that then honours it
has taken an instruction from an attacker. **And a container that cannot vouch
for its contents certainly cannot tell the verifier which algorithm to trust.**

> **⚠ This was flagged as an implementer's judgement, and
> was later promoted — with the tag requirement above — to `BV-021`.** *The
> reading has not changed; its authority has.* `cose-alg-unprotected` remains
> its own refusal code, which is now a matter of diagnostic precision rather
> than of leaving a ruling one line away.
>
> **This is the `ERR-P3-008` pattern for the second time: a judgement declared
> as the implementer's, and correct, becomes the specification's.** *That is the
> value of flagging one — a judgement carried silently cannot be promoted,
> because nobody is asked.*
"""

from __future__ import annotations

from dataclasses import dataclass

from .cbor import CborError, Tag, assert_round_trip, encode
from .ed25519 import verify as ed25519_verify

__all__ = ["CoseError", "Sign1", "COSE_SIGN1_TAG", "ALG_EDDSA",
           "HEADER_ALG", "HEADER_CRIT", "parse", "sig_structure",
           "verify_detached", "REFUSALS"]

#: RFC 9052 section 2: COSE_Sign1 is tag 18.
COSE_SIGN1_TAG = 18

#: RFC 9052 section 3.1 common header parameters.
HEADER_ALG = 1
HEADER_CRIT = 2

#: RFC 9053 section 2.2: EdDSA.
ALG_EDDSA = -8

#: The context string of RFC 9052 section 4.4 for a COSE_Sign1.
SIG_CONTEXT = "Signature1"

REFUSALS = (
    "cose-not-deterministic",
    "cose-wrong-tag",
    "cose-structure-malformed",
    "cose-protected-not-bstr",
    "cose-protected-not-a-map",
    "cose-alg-absent",
    "cose-alg-unprotected",
    "cose-alg-unsupported",
    "cose-crit-unsupported",
    "cose-payload-attached",
    "cose-signature-malformed",
    "cose-signature-does-not-verify",
)


class CoseError(Exception):
    """A refusal with a named code. `code` is one of `REFUSALS`."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class Sign1:
    """A parsed COSE_Sign1 with a detached payload.

    `protected_bytes` is kept VERBATIM and is what enters the Sig_structure.
    Re-encoding it from `protected` would make the signature depend on this
    module's encoder rather than on the signer's bytes — the same reasoning that
    makes `ERR-P3-005` carry `witness_token` opaque.
    """

    protected_bytes: bytes
    protected: dict
    unprotected: dict
    signature: bytes

    @property
    def algorithm(self) -> int:
        return self.protected[HEADER_ALG]


def parse(data: bytes) -> Sign1:
    """Parse a COSE_Sign1 with a detached payload. Raises `CoseError`.

    **The tag is REQUIRED — `BV-021`, now normative.** RFC 9052 allows
    an untagged structure where the type is known from context, but a bundle
    field named `cose_sign1` that could also hold an untagged four-item array
    gives an exporter two encodings for one thing — and **two encodings of one
    object is the defect `BV-006` exists to name.** Refusing the untagged form
    costs an exporter one byte.

    *Promoted from where it was flagged as this implementer's
    judgement. The behaviour below is unchanged; it is the authority behind it
    that moved.*
    """
    try:
        value = assert_round_trip(data)
    except CborError as exc:
        raise CoseError("cose-not-deterministic", str(exc)) from None

    if not isinstance(value, Tag) or value.number != COSE_SIGN1_TAG:
        got = f"tag {value.number}" if isinstance(value, Tag) else type(value).__name__
        raise CoseError("cose-wrong-tag",
                        f"expected the COSE_Sign1 tag {COSE_SIGN1_TAG}, got {got}")

    body = value.value
    if not isinstance(body, list) or len(body) != 4:
        raise CoseError(
            "cose-structure-malformed",
            "a COSE_Sign1 is a four-item array [protected, unprotected, payload, "
            f"signature]; got {type(body).__name__} of length "
            f"{len(body) if isinstance(body, list) else 'n/a'}")

    protected_bytes, unprotected, payload, signature = body

    if not isinstance(protected_bytes, bytes):
        raise CoseError("cose-protected-not-bstr",
                        f"the protected header is {type(protected_bytes).__name__}, "
                        "not a byte string")
    if protected_bytes == b"":
        # RFC 9052: a zero-length bstr is the empty map. Legal, and it cannot
        # carry `alg`, so it fails the next check with the accurate name.
        protected: dict = {}
    else:
        try:
            protected = assert_round_trip(protected_bytes)
        except CborError as exc:
            raise CoseError("cose-not-deterministic",
                            f"protected header: {exc}") from None
        if not isinstance(protected, dict):
            raise CoseError("cose-protected-not-a-map",
                            f"the protected header decodes to "
                            f"{type(protected).__name__}, not a map")

    if not isinstance(unprotected, dict):
        raise CoseError("cose-structure-malformed",
                        f"the unprotected header is {type(unprotected).__name__}, "
                        "not a map")

    if payload is not None:
        raise CoseError(
            "cose-payload-attached",
            "the payload is attached. The signed bytes must travel beside this "
            "structure, and carrying a value that a signed object already "
            "determines is itself a refusal -- so the two rules are "
            "consistent only with a detached payload")

    if HEADER_ALG not in protected:
        if HEADER_ALG in unprotected:
            raise CoseError(
                "cose-alg-unprotected",
                "`alg` appears only in the unprotected header, where it is not "
                "covered by the signature and can be rewritten in transit")
        raise CoseError("cose-alg-absent", "no `alg` in either header bucket")
    if protected[HEADER_ALG] != ALG_EDDSA:
        raise CoseError(
            "cose-alg-unsupported",
            f"alg {protected[HEADER_ALG]!r}; this verifier implements EdDSA "
            f"({ALG_EDDSA}) only, and will not guess another")

    if HEADER_CRIT in protected:
        crit = protected[HEADER_CRIT]
        if not isinstance(crit, list) or not crit:
            raise CoseError("cose-crit-unsupported",
                            "`crit` must be a non-empty array (RFC 9052 3.1)")
        unknown = [label for label in crit if label not in (HEADER_ALG,)]
        if unknown:
            # RFC 9052: a party that cannot process every label in `crit` MUST
            # reject. Silently ignoring one is how a "critical" extension stops
            # being critical.
            raise CoseError("cose-crit-unsupported",
                            f"critical header label(s) {unknown} not understood")

    if not isinstance(signature, bytes):
        raise CoseError("cose-signature-malformed",
                        f"the signature is {type(signature).__name__}, not a byte string")
    if len(signature) != 64:
        raise CoseError("cose-signature-malformed",
                        f"an Ed25519 signature is 64 bytes; got {len(signature)}")

    return Sign1(protected_bytes=protected_bytes, protected=protected,
                 unprotected=dict(unprotected), signature=signature)


def sig_structure(protected_bytes: bytes, payload: bytes, *,
                  external_aad: bytes = b"") -> bytes:
    """RFC 9052 section 4.4's `Sig_structure`, as the bytes actually signed.

    `["Signature1", body_protected, external_aad, payload]`. The protected bytes
    go in VERBATIM; only the surrounding array is encoded here.
    """
    return encode([SIG_CONTEXT, protected_bytes, external_aad, payload])


def verify_detached(sign1: Sign1, payload: bytes, public_key: bytes, *,
                    external_aad: bytes = b"") -> bool:
    """Verify `sign1` over detached `payload`.

    Returns a bool rather than raising, because the CALLER decides whether a
    failed signature is `REFUTED` or `ALTERED` — `CP-016`'s raise-do-not-return
    rule binds proof verifiers, whose failure is unambiguous; here the same
    False means different verdicts at different rungs, and collapsing that into
    an exception would let one call site's reading stand for all of them.
    """
    return ed25519_verify(public_key,
                          sig_structure(sign1.protected_bytes, payload,
                                        external_aad=external_aad),
                          sign1.signature)
