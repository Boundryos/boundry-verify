"""Reducing a key REPRESENTATION to the KEY IT DENOTES.

**Built from RFC 8032 §5.1.5, RFC 8410 §3 and RFC 5280 §4.1 alone.** The kernel
repository has not been read, and `INTEROP/` was not opened to write this: the
formats below are the ones these three RFCs define for an Ed25519 public key,
not the ones any artefact happens to carry.

## ⚠ Why this module exists, and it is a correction

`BV-011` as first written compared `key_material` for BYTE equality and `format`
for STRING equality. **The first interoperation run reported the bundle's key as
differing from the anchor's when they were the same key** — a certificate on one
side, the raw 32 bytes it embeds on the other. **`BV-011` is CORRECTED:
it compares KEYS, not ENCODINGS**, and *a difference in `format` alone
is not a difference in key.*

`BV-009` says `format` is *"how to interpret `key_material`"* — **which is
precisely the case in which equality of bytes is the wrong test.**

## ⚠ What a reduction is NOT

**Reducing a certificate to its subject public key is NOT validating that
certificate.** No chain is built, no signature on it is checked, no validity
window is read, no name is compared, no extension is honoured. *This module
answers one question — WHICH KEY DOES THIS REPRESENTATION DENOTE — and a caller
that reads it as "the certificate is good" has read a fact that is not here.*
The anchor is trusted because it was **provisioned**, never because it parsed.

## ⚠ Three refusals, and each names a DIFFERENT fact (`BV-028`)

| code | the fact it names | whose |
|---|---|---|
| `key-reduction-not-provisioned` | no parse bound was supplied, so nothing needing a parser can be reduced | the **operator**'s |
| `key-format-not-implemented` | this verifier holds no reducer for that format | the **verifier**'s |
| `key-material-malformed` | the material is not well-formed under the format it declares | the **material**'s |
| `key-algorithm-not-ed25519` | it is well-formed and denotes a key of another algorithm | the **material**'s |

**The first two are gaps in us and the last two are defects in the input, and
`BV-028` turns on exactly that line.** *A verifier that reports its own
inability to decode a representation as a disagreement between two parties has
manufactured a finding out of a gap in itself.*

## The principle this module is strict and liberal by

***A reducer's only job is to answer WHAT KEY THIS DENOTES, and it refuses only
when it cannot answer.*** RFC 8410 §3 requires the `AlgorithmIdentifier`
parameters field to be ABSENT for `id-Ed25519`; a parameters field that is
present does not stop the question being answerable, **so it is accepted here
and the choice is declared rather than silent.** *That is a requirement on an
encoder, and refusing to read a key because of it would convert an encoder's
defect into `BV-028`'s exact failure.*
"""

from __future__ import annotations

from . import der

__all__ = ["KeyFormError", "REFUSALS", "REDUCIBLE_FORMATS", "ED25519_RAW",
           "SPKI_DER", "X509_DER", "ID_ED25519_SPKI", "ED25519_KEY_BYTES",
           "ID_RSA_SPKI", "ID_EC_SPKI", "ID_P256", "KIND_ED25519", "KIND_RSA",
           "KIND_EC", "reduce_to_ed25519", "reduce_to_key", "describe"]

#: RFC 8410 §3: the `AlgorithmIdentifier` OID naming an Ed25519 public key in a
#: `SubjectPublicKeyInfo`. **The same arc as RFC 8419's signature algorithm.**
ID_ED25519_SPKI = "1.3.101.112"

#: RFC 8032 §5.1.5: an Ed25519 public key is exactly 32 octets.
ED25519_KEY_BYTES = 32

#: ⚠ **Landing A.** RFC 3279 §2.3.1: the `AlgorithmIdentifier`
#: OID naming an RSA public key in a `SubjectPublicKeyInfo`.
ID_RSA_SPKI = "1.2.840.113549.1.1.1"

#: ⚠⚠ **THE KIND IS RETURNED, NOT INFERRED.** `reduce_to_key` hands its caller
#: the algorithm it found, so the caller can refuse a token whose signature
#: algorithm and whose anchor disagree INSTEAD OF ATTEMPTING IT. A reducer that
#: returned bare bytes would leave the caller guessing from the length.
KIND_ED25519 = "ed25519"
KIND_RSA = "rsa"
KIND_EC = "ec"

#: ⚠ **Landing B.** RFC 5480 §2.1.1: the SPKI algorithm for an
#: elliptic-curve public key, and the named curve this build implements.
ID_EC_SPKI = "1.2.840.10045.2.1"
ID_P256 = "1.2.840.10045.3.1.7"

ED25519_RAW = "ed25519-raw"
SPKI_DER = "spki-der"
X509_DER = "x509-der"

#: **DECLARED, not provisioned.** *"whatever set you implement is
#: a provisioned or declared fact about the checker."* This set is a property of
#: this build and is published here so that a consumer can read it without
#: reading the source. **A format outside it is `NOT COMPARED`, never a
#: difference** — `BV-011` as corrected, and `BV-028` at the key layer.
REDUCIBLE_FORMATS = (ED25519_RAW, SPKI_DER, X509_DER)

#: ⚠ `BV-023` admits no default bound, so the inner `RSAPublicKey` parse gets an
#: explicit one. It is small on purpose: the structure is two integers, and a
#: bound that would admit anything larger is a bound that is not bounding.
_RSA_LIMITS = der.Limits(max_bytes=8192, max_depth=4, max_elements=16)

REFUSALS = (
    "key-reduction-not-provisioned",
    "key-format-not-implemented",
    "key-material-malformed",
    "key-algorithm-not-ed25519",
    "key-algorithm-not-reducible",
    "key-rsa-material-malformed",
    # ⚠ Landing B. THE FIRST TWO ARE OUR GAP, THE SECOND TWO ARE THE
    # KEY'S DEFECT, and the split is the whole point (`BV-028`).
    "key-ec-curve-not-implemented",
    "key-ec-point-compressed",
    "key-ec-point-invalid",
    "key-ec-material-malformed",
)


class KeyFormError(Exception):
    """A refusal with a named code. `code` is one of `REFUSALS`."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def describe() -> str:
    """One sentence naming what this build can reduce. For findings."""
    return ("this verifier reduces " + ", ".join(repr(f) for f in REDUCIBLE_FORMATS)
            + f" to an {KIND_ED25519}, {KIND_RSA} or {KIND_EC} public key")


def _algorithm_oid(element, where: str) -> str:
    """`AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPT }`.

    **Parameters are read past, not refused** — see the module docstring.
    """
    der.expect(element, der.TAG_SEQUENCE, where)
    der.fields(element, where, minimum=1, maximum=2)
    return der.oid(element.children[0], where)


def _from_spki(element, *, where: str) -> bytes:
    """RFC 8410 §3 / RFC 5280 §4.1.2.7."""
    der.expect(element, der.TAG_SEQUENCE, where)
    children = der.fields(element, where, minimum=2, maximum=2)
    algorithm = _algorithm_oid(children[0], f"{where}.algorithm")
    if algorithm != ID_ED25519_SPKI:
        raise KeyFormError(
            "key-algorithm-not-ed25519",
            f"{where} names {algorithm}; this verifier reduces only Ed25519 "
            f"({ID_ED25519_SPKI}, RFC 8410 §3) public keys")
    key = der.bit_string(children[1], f"{where}.subjectPublicKey")
    if len(key) != ED25519_KEY_BYTES:
        raise KeyFormError(
            "key-material-malformed",
            f"{where}.subjectPublicKey carries {len(key)} octet(s); RFC 8032 "
            f"§5.1.5 makes an Ed25519 public key {ED25519_KEY_BYTES}")
    return key


def _spki_any(element, *, where: str) -> tuple:
    """`(kind, material)` from a `SubjectPublicKeyInfo`, by its ALGORITHM.

    ⚠ RFC 5280 §4.1.2.7. The algorithm decides the arm; nothing is inferred
    from the key's length. An algorithm this build holds no reducer for is
    refused by name — **our gap, not the anchor's defect** (`BV-028`).
    """
    der.expect(element, der.TAG_SEQUENCE, where)
    children = der.fields(element, where, minimum=2, maximum=2)
    algorithm = _algorithm_oid(children[0], f"{where}.algorithm")
    if algorithm == ID_ED25519_SPKI:
        return (KIND_ED25519, _from_spki(element, where=where))
    if algorithm == ID_RSA_SPKI:
        return (KIND_RSA, _rsa_from_spki(children[1], where=where))
    if algorithm == ID_EC_SPKI:
        return (KIND_EC, _ec_from_spki(children[0], children[1], where=where))
    raise KeyFormError(
        "key-algorithm-not-reducible",
        f"{where} names {algorithm}; this verifier reduces "
        f"{ID_ED25519_SPKI} (Ed25519, RFC 8410 §3) and {ID_RSA_SPKI} "
        f"(RSA, RFC 3279 §2.3.1)")


def _ec_from_spki(alg_element, key_element, *, where: str) -> tuple:
    """`(qx, qy)` from an EC `SubjectPublicKeyInfo`. RFC 5480 §2.1.1, §2.2.

    ⚠⚠ **FOUR REFUSALS, AND TWO OF THEM ARE OURS WHILE TWO ARE THE KEY'S.**
    A curve this build has not implemented and a compressed point are OUR gap —
    the key is fine and we are short. A point off the curve or at infinity is
    the KEY's defect. `BV-028` at the key layer, and the difference is what an
    operator needs to know which thing to go and fix.
    """
    from . import ecdsa_p256
    fields = der.fields(alg_element, f"{where}.algorithm", minimum=1, maximum=2)
    if len(fields) < 2:
        raise KeyFormError(
            "key-ec-material-malformed",
            f"{where}.algorithm carries no namedCurve; RFC 5480 §2.1.1 requires "
            "one for id-ecPublicKey")
    curve = der.oid(fields[1], f"{where}.algorithm.namedCurve")
    if curve != ID_P256:
        raise KeyFormError(
            "key-ec-curve-not-implemented",
            f"{where} names curve {curve}; this verifier implements "
            f"prime256v1 ({ID_P256}, RFC 5480 §2.1.1.1) only — this build is "
            "short, and the key is not at fault")
    point = der.bit_string(key_element, f"{where}.subjectPublicKey")
    if not point:
        raise KeyFormError("key-ec-material-malformed",
                           f"{where}.subjectPublicKey is empty")
    if point[0] in (0x02, 0x03):
        raise KeyFormError(
            "key-ec-point-compressed",
            f"{where}.subjectPublicKey is in compressed form (RFC 5480 §2.2); "
            "this verifier reads the uncompressed form only — this build is "
            "short, and the key is not at fault")
    if point[0] != 0x04 or len(point) != 65:
        raise KeyFormError(
            "key-ec-material-malformed",
            f"{where}.subjectPublicKey is {len(point)} octet(s) with lead byte "
            f"0x{point[0]:02x}; RFC 5480 §2.2 makes an uncompressed P-256 point "
            "65 octets beginning 0x04")
    qx = int.from_bytes(point[1:33], "big")
    qy = int.from_bytes(point[33:65], "big")
    if qx == 0 and qy == 0:
        raise KeyFormError("key-ec-point-invalid",
                           f"{where} carries the point at infinity; SEC 1 §3.2.2.1")
    if not ecdsa_p256.is_on_curve(qx, qy):
        raise KeyFormError(
            "key-ec-point-invalid",
            f"{where} does not satisfy the P-256 curve equation; SEC 1 §3.2.2.1 "
            "— this is the KEY's defect, not a limit of this build")
    return (qx, qy)


def _rsa_from_spki(element, *, where: str) -> tuple:
    """`RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
    out of a `SubjectPublicKeyInfo`. RFC 3279 §2.3.1; RFC 5280 §4.1.2.7.

    ⚠ The SPKI is located STRUCTURALLY by the caller, never by search — the
    property `_from_spki` already holds, kept here rather than re-derived.
    """
    key = der.bit_string(element, f"{where}.subjectPublicKey")
    try:
        inner = der.parse(key, limits=_RSA_LIMITS)
    except der.DerError as exc:
        raise KeyFormError(
            "key-rsa-material-malformed",
            f"{where}.subjectPublicKey does not parse as an RSAPublicKey: "
            f"{exc.code}: {exc.detail}") from None
    der.expect(inner, der.TAG_SEQUENCE, f"{where}.RSAPublicKey")
    fields = der.fields(inner, f"{where}.RSAPublicKey", minimum=2, maximum=2)
    modulus = der.integer(fields[0], f"{where}.RSAPublicKey.modulus")
    exponent = der.integer(fields[1], f"{where}.RSAPublicKey.publicExponent")
    if modulus <= 0 or exponent <= 0:
        raise KeyFormError(
            "key-rsa-material-malformed",
            f"{where}.RSAPublicKey carries modulus/exponent "
            f"{modulus.bit_length()}/{exponent}; RFC 8017 §3.1 makes both "
            "positive integers")
    return (modulus, exponent)


def _from_certificate(root) -> bytes:
    """RFC 5280 §4.1. **The SPKI is located STRUCTURALLY, never by search.**

    `TBSCertificate`'s `version` is `[0] EXPLICIT ... DEFAULT v1`, so it is the
    one field whose presence shifts every index after it. *Finding the
    `SubjectPublicKeyInfo` by hunting for the first SEQUENCE that parses as one
    would make the answer depend on what else happened to parse.*
    """
    der.expect(root, der.TAG_SEQUENCE, "Certificate")
    fields = der.fields(root, "Certificate", minimum=3, maximum=3)
    tbs = fields[0]
    der.expect(tbs, der.TAG_SEQUENCE, "TBSCertificate")
    children = der.fields(tbs, "TBSCertificate", minimum=6, maximum=10)
    offset = 1 if children[0].tag == der.context(0) else 0
    index = 5 + offset
    if index >= len(children):
        raise KeyFormError(
            "key-material-malformed",
            f"TBSCertificate carries {len(children)} field(s) and its "
            f"subjectPublicKeyInfo would be at index {index}; RFC 5280 §4.1 "
            "places it after subject")
    return _from_spki(children[index], where="TBSCertificate.subjectPublicKeyInfo")


def reduce_to_key(key_material, fmt, *, limits) -> tuple:
    """`(kind, material)` for `key_material` under `fmt`.

    ⚠⚠ **Landing A.** `reduce_to_ed25519` answered with bare
    bytes, so a caller holding an RSA anchor and an Ed25519 token — or the
    reverse — had nothing to compare and could only attempt the verification and
    report that it failed. **That would name the wrong party's fact** (`BV-028`):
    a kind mismatch is the operator's provisioning, not evidence about the
    record. This returns the kind so the caller can refuse BY NAME.

    `kind` is `KIND_ED25519` with 32 raw octets, or `KIND_RSA` with `(n, e)`.
    """
    return _reduce(key_material, fmt, limits=limits)


def reduce_to_ed25519(key_material, fmt, *, limits) -> bytes:
    """The 32 raw Ed25519 octets `key_material` denotes under `fmt`.

    ⚠⚠ **UNCHANGED LANDING A, DELIBERATELY.** Every existing
    caller keeps this name, this signature and this behaviour: an anchor that
    reduces to anything but Ed25519 raises `key-algorithm-not-ed25519`, exactly
    as before. The RSA arm is reached through `reduce_to_key`, so **no caller
    moves and nothing that worked before is re-tested by this landing.**
    """
    kind, material = _reduce(key_material, fmt, limits=limits)
    if kind != KIND_ED25519:
        raise KeyFormError(
            "key-algorithm-not-ed25519",
            f"the material reduces to a {kind} public key; this entry point "
            f"answers only {KIND_ED25519}. Use reduce_to_key for the kind.")
    return material


def _reduce(key_material, fmt, *, limits) -> tuple:
    """`(kind, material)`. The body `reduce_to_ed25519` carried until
    landing A, with the kind now named rather than assumed.

    Raises `KeyFormError`, whose `code` names **whose** fact stopped it.

    `limits` is **provisioned with no default** (`BV-023`) and is required for
    every format that needs a parser. `ed25519-raw` needs none, so it is
    reducible with `limits=None` — *the bound exists to stop an unbounded walk,
    and there is no walk over 32 flat octets.*
    """
    if not isinstance(fmt, str):
        raise KeyFormError("key-material-malformed",
                           f"the declared format is {type(fmt).__name__}, not text")
    if fmt not in REDUCIBLE_FORMATS:
        raise KeyFormError("key-format-not-implemented",
                           f"{fmt!r} is not a representation this verifier can "
                           f"reduce; {describe()}")
    if not isinstance(key_material, (bytes, bytearray)):
        raise KeyFormError("key-material-malformed",
                           f"key material is {type(key_material).__name__}, not a "
                           "byte string")
    key_material = bytes(key_material)

    if fmt == ED25519_RAW:
        if len(key_material) != ED25519_KEY_BYTES:
            raise KeyFormError(
                "key-material-malformed",
                f"{ED25519_RAW!r} carries {len(key_material)} octet(s); RFC 8032 "
                f"§5.1.5 makes an Ed25519 public key {ED25519_KEY_BYTES}")
        return (KIND_ED25519, key_material)

    if limits is None:
        raise KeyFormError(
            "key-reduction-not-provisioned",
            f"{fmt!r} must be parsed to be reduced and no parse bound was "
            "provisioned (there is no default)")
    if not isinstance(limits, der.Limits):
        raise TypeError("limits must be a der.Limits; there is no default")

    try:
        root = der.parse(key_material, limits=limits)
    except der.DerError as exc:
        raise KeyFormError("key-material-malformed",
                           f"{fmt!r}: {exc.code}: {exc.detail}") from None
    try:
        if fmt == SPKI_DER:
            return _spki_any(root, where="SubjectPublicKeyInfo")
        return (KIND_ED25519, _from_certificate(root))
    except der.DerError as exc:
        raise KeyFormError("key-material-malformed",
                           f"{fmt!r}: {exc.code}: {exc.detail}") from None
