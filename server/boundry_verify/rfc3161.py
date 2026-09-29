"""RFC 3161 `TimeStampToken` — structure only. STOP-A.

**Built from RFC 3161, RFC 5652 (CMS), RFC 5280 and RFC 8419 alone.** The kernel
repository has not been read; **`substrate/witness/` has not been opened, not
glanced at, not "just to check."** *If the kernel's client and this checker
disagree, that disagreement is the finding the separation exists to produce.*

## This module parses. It does not verify and it returns no verdict.

STOP-A's whole content: **a bounded parser and a named refusal for every way a
token can fail to be one.** Signature verification, the `messageImprint`
comparison and the reason codes are STOP-B, in `token_rfc3161.py`.

## ⚠ Five things that are deliberate, and each would be easy to get wrong

**1 · `genTime` is REPORTED, NEVER JUDGED.** Its syntax is checked — a
malformed time is a malformed token — and **its value is never compared to
anything, here or anywhere downstream.** *A verifier does not know what time it
is in any sense a record can rely on, and a checker that rejects a token for
being too old has substituted its own clock for evidence.*

**2 · The `sid` is READ and REPORTED and NEVER USED TO SELECT A KEY.** RFC 5652
lets a `SignerInfo` name its signer, and *a checker that resolved a key from
that name would be taking key material on the token's own say-so* — `BV-010`
one layer in. **The key comes from the `Anchor` and from nowhere else**, so the
`sid` here is diagnostic text and has no path to a signature check.

**3 · THE ADMITTED SET, and anything outside it is refused BY NAME.**
`ADMITTED_SIGNATURE_ALGORITHMS` is this module's own answer: Ed25519
(RFC 8419), the three `sha*WithRSAEncryption` identifiers (RFC 8017 A.2.4),
`rsaEncryption` (RFC 3370 §3.2) and `ecdsa-with-SHA256` (RFC 5758 §3.2). Each
was built from its specification, standard library only. A token signed under
any other identifier hits `tst-signature-algorithm-unsupported`.

⚠⚠ **THIS PARAGRAPH SAID "Ed25519 ONLY" AND SAID COMMERCIAL AUTHORITIES
"overwhelmingly sign with RSA or ECDSA".** The first became false at
 landings A and B. The second was a claim about a population this
programme has never measured, and it is simply dropped: **the admitted set is
a fact this module can state, and a prevalence claim is not.** *What WAS
measured: OpenSSL's own TSA emits `rsaEncryption`, which the set
 did not admit.* *That is a limitation of this pack, not
a finding against the token, and the refusal says so* — because a checker that
reported "does not verify" for a token it never attempted would invert
`ERR-P3-008` inside a single function.

**4 · `signed_attrs_der` is built by substituting ONE identifier octet**, as
RFC 5652 §5.4 requires: the `[0] IMPLICIT` tag becomes `SET OF` for signing.
**The content octets are the signer's, verbatim.** *Re-encoding the attributes
from parsed values would make the signature depend on this module's encoder
rather than on the signer's bytes* — `ERR-P3-005`'s reasoning, one layer down.

**5 · ⚠ THE `SignerInfo` DIGEST ALGORITHM IS READ FROM THE TOKEN, NOT REQUIRED
OF IT — REPAIRED ** *Until this pack the parser refused any
`digestAlgorithm` that was not `id-sha256`, and that refusal was a defect.*

**RFC 5652 §5.3 makes `digestAlgorithm` the algorithm THE SIGNER USED**, and
§5.4 computes the `messageDigest` attribute over the `eContent` **under that
algorithm**. **RFC 8419 §3.1 then REQUIRES `id-sha512` whenever the CMS
signature is Ed25519.** So a checker that accepted only Ed25519 signatures
while requiring `id-sha256` digests ***could not verify any conforming token of
the only kind it accepted*** — the two constraints were mutually exclusive and
nothing in the code said so.

**`messageImprint` DID NOT CHANGE and must not.** `ERR-P3-004` fixes the digest
this programme ATTESTS UNDER as SHA-256; the CMS `digestAlgorithm` is what the
SIGNATURE is computed under. ***Two different digests doing two different jobs,
and assuming they must match is exactly the assumption this repair removes.***

**The set below is DECLARED**, — a published fact about this
build, taken from RFC 5754 §2's four SHA-2 identifiers, **not from any token.**

## ⚠ 6 · THE ESS SIGNING-CERTIFICATE ATTRIBUTE IS REQUIRED — `BV-029`,
##

**RFC 3161 §2.4.1 requires a `TimeStampToken` to identify the certificate the
TSA signed under.** Until this pack **this checker did not require it and
attested a token that had none** — and no instrument this programme owns could
have shown that, because every fixture on both sides happened to carry it.

***It was found by an artefact we did not mint.*** `X-05` carried an
OpenSSL `cms -sign` token, which omits the attribute; this build returned
`token-verified` and OpenSSL's own RFC 3161 verifier returned FAILED, on the
same bytes, over this one field.

**Its absence is the TOKEN's defect** — `REFUTED`, never `BV-028`'s "we are
short". **Its CONTENTS are not parsed**: this checker builds no certificate
chain, so it has nothing to compare an `ESSCertID` against, and presence is
exactly what is claimed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import der
from . import rsa_pkcs1

__all__ = ["Rfc3161Error", "MessageImprint", "TstInfo", "TimeStampToken",
           "parse_token", "REFUSALS", "ID_SIGNED_DATA", "ID_CT_TST_INFO",
           "ID_ATTR_CONTENT_TYPE", "ID_ATTR_MESSAGE_DIGEST",
           "ID_ATTR_SIGNING_TIME", "ID_ATTR_SIGNING_CERTIFICATE",
           "ID_ATTR_SIGNING_CERTIFICATE_V2", "ESS_SIGNING_CERTIFICATE_ATTRS",
           "SINGLE_VALUE_REQUIRED", "ID_SHA256",
           "ID_SHA384", "ID_SHA512", "ID_SHA224", "ID_ED25519",
           "DIGEST_ALGORITHMS", "SIGNATURE_DIGEST_REQUIREMENTS", "digest_for",
           "ID_RSA_ENCRYPTION", "ADMITTED_SIGNATURE_ALGORITHMS",
           "RSA_ENCRYPTION_DIGESTS", "RSA_DIGEST_PAIRING_POLICY"]

ID_SIGNED_DATA = "1.2.840.113549.1.7.2"
ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4"
ID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3"
ID_ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
ID_ATTR_SIGNING_TIME = "1.2.840.113549.1.9.5"
#: RFC 2634 §5.4 and RFC 5035 §3 — the two forms of the ESS signing-certificate
#: attribute. **`BV-029`**; see `ESS_SIGNING_CERTIFICATE_ATTRS`.
ID_ATTR_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12"
ID_ATTR_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"

#: ⚠ **RFC 5652 section 11, AS A TABLE AND NOT AS AN `if`** — the same shape as
#: `SIGNATURE_DIGEST_REQUIREMENTS` above, and for the same reason.
#:
#: **Sections 11.1, 11.2 and 11.3 each REQUIRE their attribute to carry exactly
#: one value**, in so many words: a single attribute value, *even though the
#: syntax is defined as a `SET OF AttributeValue`*. **So a `content-type`,
#: `message-digest` or `signing-time` attribute carrying any other number of
#: values is a defect IN THE TOKEN**, and a multi-valued attribute CMS does not
#: so constrain is **THIS BUILD being short**. *:
#: one refusal code was covering both classes — which is precisely the defect
#: `rfc3161-token-malformed` was split to remove, reproduced one level down in
#: the code that replaced it.*
#:
#: `signing-time` is listed although nothing here READS it: the requirement is
#: the standard's, not this checker's, and a table that only named the fields we
#: happen to consume would be an enumeration of our own use.
SINGLE_VALUE_REQUIRED = {
    ID_ATTR_CONTENT_TYPE: "RFC 5652 section 11.1",
    ID_ATTR_MESSAGE_DIGEST: "RFC 5652 section 11.2",
    ID_ATTR_SIGNING_TIME: "RFC 5652 section 11.3",
}

#: ⚠ **`BV-029`, AS A TABLE AND NOT AS AN `if`** — the third table on this path,
#: for the third time for the same reason.
#:
#: **RFC 3161 section 2.4.1 REQUIRES a `TimeStampToken` to identify the
#: certificate the TSA signed under, carried as a signed ESS attribute.** Two
#: forms satisfy it: `signingCertificate` (RFC 2634 section 5.4, `ESSCertID`,
#: SHA-1 hashes) and `signingCertificateV2` (RFC 5035 section 3, `ESSCertIDv2`,
#: any hash). **EITHER discharges the requirement; NEITHER present is a token
#: that is malformed on its face.**
#:
#: ***This is a requirement on the TOKEN, so its absence is `_DEFECT` and
#: `REFUTED` — never `BV-028`'s "we are short". Nothing is missing from this
#: checker.*** *`BV-029` is explicit on the point and it is the whole reason the
#: clause was minted.*
#:
#: ⚠ **THE ATTRIBUTE'S CONTENTS ARE NOT PARSED AND NOTHING IS COMPARED TO A
#: CERTIFICATE.** This checker builds no chain (`BV-010`; the module docstring
#: of `token_rfc3161`), so it has no certificate to compare an `ESSCertID`
#: against and would be inventing a validator if it tried. **What is asserted is
#: exactly what is checked: the mandatory attribute is PRESENT.** *Checking the
#: hash inside it against a chain we do not build would be a second wire format
#: invented by the consumer — and claiming more than presence is how a partial
#: check becomes a whole claim.*
ESS_SIGNING_CERTIFICATE_ATTRS = {
    ID_ATTR_SIGNING_CERTIFICATE: "signingCertificate (RFC 2634 section 5.4)",
    ID_ATTR_SIGNING_CERTIFICATE_V2:
        "signingCertificateV2 (RFC 5035 section 3)",
}
#: `ERR-P3-004`'s digest, and the ONLY thing this constant governs after
#: The `messageImprint`'s `hashAlgorithm`. **It is no longer the
#: CMS `digestAlgorithm` gate** -- see `DIGEST_ALGORITHMS`.
ID_SHA256 = "2.16.840.1.101.3.4.2.1"
#: RFC 5754 §2's other three SHA-2 identifiers.
ID_SHA384 = "2.16.840.1.101.3.4.2.2"
ID_SHA512 = "2.16.840.1.101.3.4.2.3"
ID_SHA224 = "2.16.840.1.101.3.4.2.4"
#: RFC 8410 / RFC 8419: Ed25519 in CMS. **The only signature algorithm this
#: checker implements** -- see `REFUSALS`' `tst-signature-algorithm-unsupported`
#: and the note in `token_rfc3161.py`.
ID_ED25519 = "1.3.101.112"

#: ⚠⚠ **Landing A.** RSASSA-PKCS1-v1_5 with SHA-2, RFC 8017
#: A.2.4. ⚠⚠ **THIS COMMENT CLAIMED COMMERCIAL AUTHORITIES "overwhelmingly
#: sign with these".** That is a claim about a population this programme has
#: never measured, and measured the one implementation it had to hand:
#: **OpenSSL's TSA signs with `rsaEncryption`, not with these**, and `openssl
#: ts` has no setting that changes it. The claim is dropped rather than
#: restated. These three identifiers are admitted; `ID_RSA_ENCRYPTION` below
#: is admitted too, and which one an authority chooses is not asserted here.
#:
#: ⚠ These are module-level STRINGS, not a collection: `vocabulary_sweep`
#: discovers no new subject and `ROWS` does not move. The pairing rows below
#: are keyed by these NAMES for the same reason.
ID_RSA_SHA256 = "1.2.840.113549.1.1.11"
ID_RSA_SHA384 = "1.2.840.113549.1.1.12"
ID_RSA_SHA512 = "1.2.840.113549.1.1.13"

#: ⚠ **Landing B.** ECDSA with SHA-256 over P-256, RFC 5758
#: §3.2. ⚠ `ecdsa-with-SHA384` (…4.3.3) and `ecdsa-with-SHA512` (…4.3.4) are
#: **NOT** admitted: they reach `tst-signature-algorithm-unsupported`, which is
#: THIS BUILD being short and not a finding against the token.
ID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"

#: ⚠⚠ **Landing B. THE IDENTIFIER CMS MAKES *MUST*-SUPPORT.**
#: RFC 3370 §3.2: *"The rsaEncryption algorithm identifier is used to identify
#: RSA (PKCS #1 v1.5) signature values regardless of the message digest
#: algorithm employed. CMS implementations that include the RSA (PKCS #1 v1.5)
#: signature algorithm MUST support the rsaEncryption signature value algorithm
#: identifier, and CMS implementations MAY support RSA (PKCS #1 v1.5) signature
#: value algorithm identifiers that specify both the RSA (PKCS #1 v1.5)
#: signature algorithm and the message digest algorithm."*
#:
#: ***Landing A admitted only the MAY-support identifiers and omitted this one.***
#: OpenSSL's own timestamp authority emits `rsaEncryption`, and `openssl ts` has
#: no setting that changes it -- so every token it issues reached
#: `tst-signature-algorithm-unsupported`. Measured, not assumed.
ID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"

#: **DECLARED, not provisioned**. The CMS message-digest
#: algorithms this build performs, by RFC 5754 §2's identifiers. A `SignerInfo`
#: digesting under anything else is refused BY NAME as unsupported --
#: ***a fact about this checker, and never a finding against the token.***
DIGEST_ALGORITHMS = {
    ID_SHA224: ("id-sha224", hashlib.sha224),
    ID_SHA256: ("id-sha256", hashlib.sha256),
    ID_SHA384: ("id-sha384", hashlib.sha384),
    ID_SHA512: ("id-sha512", hashlib.sha512),
}

#: ⚠ **RFC 8419 §3.1, AS A TABLE AND NOT AS AN `if`.** *"When signing with
#: Ed25519, the digestAlgorithm MUST be id-sha512."* The pairing is a property
#: of the SIGNATURE algorithm, so it is keyed by one.
#:
#: ⚠⚠ **THIS COMMENT SAID "a second signature algorithm adds a row here and
#: changes no code". LANDING B MAKES THAT FALSE**, and it
#: is corrected rather than left standing. `rsaEncryption` (`ID_RSA_ENCRYPTION`)
#: has **no single required digest** -- RFC 3370 §3.2 says it identifies an RSA
#: PKCS#1 v1.5 signature *"regardless of the message digest algorithm
#: employed"* -- so it takes no row here at all. It is admitted by
#: `ADMITTED_SIGNATURE_ALGORITHMS` below and its hash is READ from the
#: `SignerInfo`'s own `digestAlgorithm`. *A table keyed by "the one digest this
#: signature algorithm requires" cannot express an algorithm that requires
#: none, and forcing a row in would have invented a requirement no RFC states.*
#:
#: This is a CONFORMANCE requirement on the token, which is why violating it is
#: a different refusal from digesting under something this checker lacks:
#: **one says the token is wrong, the other says WE are short**, and
#: `BV-028` turns on precisely that line.
SIGNATURE_DIGEST_REQUIREMENTS = {
    ID_ED25519: (ID_SHA512, "RFC 8419 §3.1"),
    # ⚠⚠ **THE THREE RSA ROWS LEFT THIS TABLE AT `BV-028`, 15 September 2026.**
    # They claimed RFC 5754 §3.2 as a CONFORMANCE requirement on the token, and
    # **that section contains no sentence pairing `digestAlgorithm` with the hash
    # a signature OID names.** The rows are not deleted: they are
    # `RSA_DIGEST_PAIRING_POLICY` below, and what they produce is now a refusal
    # that names THIS CHECKER's limit. *A verdict against a record needs a rule
    # the record broke.*
    # ⚠ **CITATION CORRECTED BEFORE LANDING, §A.6.** This row cited
    # "RFC 5758 §3.2", which covers ECDSA OIDs in CERTIFICATES AND CRLs and
    # says nothing about the CMS `digestAlgorithm`. The rule is RFC 5753
    # §2.1.1: *"The hash algorithm identified in the name of the signature
    # algorithm MUST be the same as the digestAlgorithm (e.g., digestAlgorithm
    # is id-sha256 therefore signatureAlgorithm is ecdsa-with-SHA256)."*
    ID_ECDSA_SHA256: (ID_SHA256, "RFC 5753 §2.1.1"),
}

#: ⚠⚠ **THIS PACK'S POLICY, AND NO RFC IS CITED FOR IT** (`BV-028`, ruled
#: 15 September 2026, option (i)).
#:
#: Each `sha*WithRSAEncryption` identifier names a hash, and **this checker
#: declines to verify a signature whose `SignerInfo.digestAlgorithm` says
#: something else.** That is a limit this pack sets for itself: no RFC this
#: module cites requires the pairing, and RFC 3370 §3.2 says the RSA identifier
#: applies *"regardless of the message digest algorithm employed"*.
#:
#: ***So the refusal names OUR limit and never the token's defect.*** It carries
#: `tst-digest-algorithm-pairing-declined`, classed `_SHORT`. Until this ruling
#: these three rows sat in `SIGNATURE_DIGEST_REQUIREMENTS` beside Ed25519's and
#: ECDSA's, whose pairing sentences are quoted above, and a mispaired RSA token
#: was REFUTED — an accusation resting on a citation that does not state the
#: rule.
#:
#: ⚠ **The value is the digest alone, with no citation field**, unlike the
#: table above. There is nothing to put there, and a shape that cannot hold a
#: citation cannot pretend to one.
RSA_DIGEST_PAIRING_POLICY = {
    ID_RSA_SHA256: ID_SHA256,
    ID_RSA_SHA384: ID_SHA384,
    ID_RSA_SHA512: ID_SHA512,
}

#: ⚠ **DERIVED, never enumerated**. The signature algorithms this
#: build admits: every algorithm with a required-digest row above, plus
#: `rsaEncryption`, which has no such row by RFC 3370 §3.2. *Typing the six out
#: again would be a second list to disagree with the first.*
ADMITTED_SIGNATURE_ALGORITHMS = (frozenset(SIGNATURE_DIGEST_REQUIREMENTS)
                                 | frozenset(RSA_DIGEST_PAIRING_POLICY)
                                 | {ID_RSA_ENCRYPTION})

#: ⚠ **DERIVED from the RSA verifier's own `DigestInfo` table**:
#: the digests this build can actually perform an RSASSA-PKCS1-v1_5
#: verification under. A token declaring `rsaEncryption` beside any other
#: digest -- `id-sha224` included, which `DIGEST_ALGORITHMS` above performs
#: perfectly well -- is refused as **THIS BUILD being short**, never as the
#: token's defect. *The two tables cannot drift apart because there is only one.*
#: ⚠ The two tables are keyed differently -- `DIGEST_ALGORITHMS` by OID,
#: `DIGEST_INFO_PREFIXES` by hash NAME -- so the derivation joins them on the
#: name rather than assuming they share a key. *The first spelling of this line
#: was `frozenset(rsa_pkcs1.DIGEST_INFO_PREFIXES)`, a set of NAMES compared
#: against an OID, which would have refused every `rsaEncryption` token as a
#: digest this build lacks. Caught by the vectors before it left scratch.*
RSA_ENCRYPTION_DIGESTS = frozenset(
    oid_ for oid_, (name, _ctor) in DIGEST_ALGORITHMS.items()
    if name.removeprefix("id-") in rsa_pkcs1.DIGEST_INFO_PREFIXES)

REFUSALS = (
    "tst-not-content-info",
    "tst-not-signed-data",
    "tst-signed-data-version",
    "tst-wrong-econtent-type",
    "tst-no-econtent",
    "tst-signer-count",
    "tst-signer-version",
    "tst-no-signed-attrs",
    "tst-attr-malformed",
    "tst-attr-single-value-required",
    "tst-attr-values-not-a-set",
    "tst-duplicate-attr",
    "tst-missing-content-type-attr",
    "tst-content-type-attr-mismatch",
    "tst-missing-message-digest-attr",
    "tst-missing-signing-certificate-attr",
    "tst-digest-algorithm-unsupported",
    "tst-digest-algorithm-not-permitted",
    # ⚠ `BV-028`, 15 September 2026. The pairing this pack declines by POLICY,
    # as against `not-permitted` above, which a standard requires.
    "tst-digest-algorithm-pairing-declined",
    "tst-signature-algorithm-unsupported",
    # ⚠ landing B. RFC 3370 §3.2 fixes `rsaEncryption`'s
    # parameters at NULL; RFC 5754 §2's accept-both licence is about SHA-2
    # DIGEST identifiers, not this one. A parameters field that is neither NULL
    # nor absent is the TOKEN's defect.
    "tst-signature-algorithm-parameters-invalid",
    "tst-imprint-algorithm-unsupported",
    "tst-info-version",
    "tst-structure",
    "tst-provisioned-bound-exceeded",
)

_CONTEXT_0_CONSTRUCTED = der.context(0)
_CONTEXT_0_PRIMITIVE = der.context(0, constructed=False)
_CONTEXT_1_CONSTRUCTED = der.context(1)


class Rfc3161Error(Exception):
    """A refusal with a named code. `code` is one of `REFUSALS`."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class MessageImprint:
    """RFC 3161 §2.4.1. The digest the TSA says it stamped."""

    hash_algorithm: str
    hashed_message: bytes


@dataclass(frozen=True)
class TstInfo:
    """RFC 3161 §2.4.2, as parsed. **`gen_time` is text and is never judged.**"""

    version: int
    policy: str
    message_imprint: MessageImprint
    serial_number: int
    gen_time: str
    accuracy_present: bool
    ordering: bool
    nonce: int | None
    tsa_present: bool
    extensions_present: bool


@dataclass(frozen=True)
class TimeStampToken:
    """A parsed token. **Nothing here has been verified.**"""

    tst_info: TstInfo
    #: The DER of TSTInfo, VERBATIM as the signer emitted it.
    econtent: bytes
    #: The bytes RFC 5652 §5.4 says are signed: signedAttrs re-tagged SET OF.
    signed_attrs_der: bytes
    signed_attr_content_type: str
    signed_attr_message_digest: bytes
    #: The `SignerInfo`'s `digestAlgorithm` OID, **READ from the token**. The
    #: `messageDigest` attribute is computed under THIS and not under a
    #: constant (RFC 5652 §5.3, §5.4).
    digest_algorithm: str
    #: `True` when that `AlgorithmIdentifier` carried a parameters field.
    #: **Reported, never judged** — RFC 8419 §3.1 against RFC 5754 §2.
    digest_algorithm_parameters_present: bool
    #: `SignedData.digestAlgorithms`, RFC 5652 §5.1's collection. Carried so a
    #: checker can REPORT whether the signer's algorithm was declared there.
    #: **RFC 5652 §5.1 makes that a SHOULD, so it is a finding and never a
    #: refusal.**
    signed_data_digest_algorithms: tuple
    signature_algorithm: str
    signature: bytes
    #: Diagnostic only. **Never used to select a key.**
    sid_description: str
    certificates_present: bool
    #: Which ESS signing-certificate attribute discharged `BV-029`. **The
    #: attribute's presence is REQUIRED; its CONTENTS are not parsed and are
    #: compared to nothing** — this checker builds no chain, so it holds no
    #: certificate to compare an `ESSCertID` against. *Diagnostic text.*
    ess_signing_certificate: str


def _from_der_error(exc, where: str, limits=None) -> "Rfc3161Error":
    """Convert a `der.DerError` into this layer's refusal — **by the der CODE,
    never by the raise site.**

    ⚠ **A PROVISIONED BOUND BEING REACHED IS NOT THE TOKEN BEING WRONG.** Three
    of `der`'s refusals are `Limits` fields the OPERATOR chose
    (`der.PROVISIONED_BOUND_REFUSALS`). *The clean token that verifies under
    generous limits was refused as `REFUTED` under a smaller `max_bytes` — the
    check never ran, nothing was learned about the record, and `BV-028` calls
    that "we are short".*

    **Every other `der.DerError` is a defect in the bytes and keeps
    `tst-structure`.**

    > ⚠ **WHY THIS KEYS ON THE CODE AND NOT ON THE SITE, MEASURED RATHER THAN
    > ASSUMED.** describes *"three bound-related `tst-structure`
    > sites"*. **There are three bound-related der CODES and they reach TWO
    > different raise sites** — the top-level `der.parse` in `parse_token`, and
    > the inner `der.parse` of the `eContent` in `_parse_tst_info`, which fires
    > when a token's `TSTInfo` is nested deeply enough that the outer walk passes
    > and the inner one does not. ***And both of those sites also carry genuine
    > syntax defects.*** **So there is no set of sites that separates the two
    > classes, and a repair keyed on sites would have been wrong in both
    > directions.**

    `limits` is passed where the caller holds it, so the refusal can name the
    provisioned VALUE and not merely the bound. **Where it is absent the bound
    is still named** — a refusal that cannot state the value is still the right
    class, and silently guessing one would be worse.
    """
    if exc.code in der.PROVISIONED_BOUND_REFUSALS:
        field = der.BOUND_FIELD[exc.code]
        value = getattr(limits, field, None) if limits is not None else None
        stated = (f"provisioned at {value}" if value is not None
                  else "provisioned value not in scope at this call site")
        return Rfc3161Error(
            "tst-provisioned-bound-exceeded",
            (f"{where}: " if where else "") +
            f"the parse reached {field}, {stated}, and stopped "
            f"({exc.code}). THIS BUILD was bounded and the check never ran, so "
            "nothing whatever is asserted about the token: a token larger, "
            "deeper or busier than a limit THIS OPERATOR chose is not a token "
            "that is wrong. Raise the bound to obtain a verdict")
    return Rfc3161Error("tst-structure", f"{where}: {exc}" if where else str(exc))


def _seq(element, where: str, *, minimum: int, maximum: int):
    try:
        der.expect(element, der.TAG_SEQUENCE, where)
        return der.fields(element, where, minimum=minimum, maximum=maximum)
    except der.DerError as exc:
        raise _from_der_error(exc, "") from None


def _wrap(where: str, fn):
    try:
        return fn()
    except der.DerError as exc:
        raise _from_der_error(exc, where) from None


def digest_for(oid_: str):
    """The hash constructor `oid_` names, or `None` if this build lacks it.

    **The only place a digest algorithm identifier becomes a function**, so
    every caller digests under the algorithm the TOKEN declared rather than
    under one it assumed. *`token_rfc3161` reaches this through
    `TimeStampToken.digest_algorithm`, which is read and not required.*
    """
    entry = DIGEST_ALGORITHMS.get(oid_)
    return entry[1] if entry else None


def _algorithm_id(element, where: str) -> str:
    """`AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPT }`."""
    return _algorithm_id_full(element, where)[0]


def _algorithm_id_full(element, where: str) -> tuple[str, bool]:
    """The same, also reporting **whether a parameters field is present.**

    ⚠ **Present parameters are ACCEPTED and REPORTED, never refused, and the
    two RFCs in play disagree about them.** RFC 8419 §3.1 says the parameters
    field MUST be absent for an Ed25519 CMS signature and its digest; RFC 5754
    §2 says an implementation MUST ACCEPT a SHA-2 `AlgorithmIdentifier` both
    with absent parameters and with NULL parameters.

    ***A "MUST be absent" binds the encoder and a "MUST accept" binds us***, so
    this reader accepts both and hands the observation to the findings channel
    (`BV-024`), where it is reported and cannot move a verdict. *Refusing here
    would make an encoder's defect into a refusal of a key we can plainly read
    — `BV-028`'s failure in a smaller place.*
    """
    children = _seq(element, where, minimum=1, maximum=2)
    return _wrap(where, lambda: der.oid(children[0], where)), len(children) == 2


def _algorithm_id_params(element, where: str) -> tuple[str, bool, bool]:
    """The identifier, whether parameters are present, **and whether NULL.**

    ⚠ landing B. `_algorithm_id_full` above reports only
    PRESENCE, because the policy it documents is about absent-versus-NULL,
    where RFC 8419 §3.1 and RFC 5754 §2 disagree and this reader accepts both.
    **RFC 3370 §3.2 leaves no such room for `rsaEncryption`: its parameters are
    NULL.** A field that is neither NULL nor absent is not an encoder's choice
    between two readings of two RFCs; it is a defect, and it gets a name.
    """
    children = _seq(element, where, minimum=1, maximum=2)
    oid_ = _wrap(where, lambda: der.oid(children[0], where))
    if len(children) == 1:
        return oid_, False, False
    params = children[1]
    return oid_, True, (params.tag == der.TAG_NULL and not params.content)


def _parse_message_imprint(element) -> MessageImprint:
    children = _seq(element, "TSTInfo.messageImprint", minimum=2, maximum=2)
    algorithm = _algorithm_id(children[0], "messageImprint.hashAlgorithm")
    if algorithm != ID_SHA256:
        # ⚠ Named, not silently accepted. ERR-P3-004 fixes the digest this
        # programme attests to as SHA-256; a token imprinting under another
        # algorithm is not a token about this checkpoint, and guessing which
        # would be inventing the witness's profile.
        raise Rfc3161Error(
            "tst-imprint-algorithm-unsupported",
            f"messageImprint uses {algorithm}; this checker implements SHA-256 "
            f"({ID_SHA256}) only, which is what a receipt attests under")
    digest = _wrap("messageImprint.hashedMessage",
                   lambda: der.octets(children[1], "messageImprint.hashedMessage"))
    return MessageImprint(hash_algorithm=algorithm, hashed_message=digest)


def _parse_tst_info(econtent: bytes, limits: der.Limits) -> TstInfo:
    try:
        root = der.parse(econtent, limits=limits)
    except der.DerError as exc:
        raise _from_der_error(exc, "TSTInfo", limits) from None
    children = _seq(root, "TSTInfo", minimum=5, maximum=10)

    version = _wrap("TSTInfo.version", lambda: der.integer(children[0], "TSTInfo.version"))
    if version != 1:
        raise Rfc3161Error("tst-info-version",
                           f"TSTInfo version {version}; RFC 3161 defines v1 only")
    policy = _wrap("TSTInfo.policy", lambda: der.oid(children[1], "TSTInfo.policy"))
    imprint = _parse_message_imprint(children[2])
    serial = _wrap("TSTInfo.serialNumber",
                   lambda: der.integer(children[3], "TSTInfo.serialNumber"))
    gen_time = _wrap("TSTInfo.genTime",
                     lambda: der.generalized_time(children[4], "TSTInfo.genTime"))

    # The optional tail, in RFC 3161's declared order. Each is RECOGNISED and
    # reported; none is interpreted, because none of them bears on whether the
    # token attests to our digest under an anchored key.
    accuracy = ordering = tsa = extensions = False
    nonce = None
    rest = list(children[5:])
    if rest and rest[0].tag == der.TAG_SEQUENCE:
        accuracy = True
        rest.pop(0)
    if rest and rest[0].tag == der.TAG_BOOLEAN:
        ordering = _wrap("TSTInfo.ordering",
                         lambda: der.boolean(rest[0], "TSTInfo.ordering"))
        if ordering is False:
            # DER omits a field equal to its DEFAULT. An explicit FALSE is a
            # second encoding of the same TSTInfo.
            raise Rfc3161Error("tst-structure",
                               "TSTInfo.ordering is present and FALSE; DER omits a "
                               "field at its DEFAULT, so this is a second encoding")
        rest.pop(0)
    if rest and rest[0].tag == der.TAG_INTEGER:
        nonce = _wrap("TSTInfo.nonce", lambda: der.integer(rest[0], "TSTInfo.nonce"))
        rest.pop(0)
    if rest and rest[0].tag == _CONTEXT_0_CONSTRUCTED:
        tsa = True
        rest.pop(0)
    if rest and rest[0].tag == _CONTEXT_1_CONSTRUCTED:
        extensions = True
        rest.pop(0)
    if rest:
        raise Rfc3161Error("tst-structure",
                           f"TSTInfo carries {len(rest)} field(s) after extensions, "
                           f"first tag 0x{rest[0].tag:02x}; RFC 3161 closes this "
                           "SEQUENCE")

    return TstInfo(version=version, policy=policy, message_imprint=imprint,
                   serial_number=serial, gen_time=gen_time,
                   accuracy_present=accuracy, ordering=ordering, nonce=nonce,
                   tsa_present=tsa, extensions_present=extensions)


def _require_ess_signing_certificate(seen: dict) -> str:
    """`BV-029`. Refuse unless an ESS signing-certificate attribute is present.

    Returns which form discharged it, as diagnostic text.

    ⚠ **A NAMED FUNCTION RATHER THAN AN INLINE `if`, DELIBERATELY.** `BV-029`
    requires the assertion to be proven by a NEGATIVE VECTOR — an artefact that
    violates the requirement — **and a mutation campaign proves the assertion is
    load-bearing by REMOVING it and watching a probe die.** *A guard buried
    inside a larger function has no patch target, so the mutation that removes
    it would have to reproduce the whole function, and a reproduced function
    drifts from the one it is testing.* **`RM21` patches this name; `RP45` kills
    it.**
    """
    present = [oid_ for oid_ in ESS_SIGNING_CERTIFICATE_ATTRS if oid_ in seen]
    if not present:
        raise Rfc3161Error(
            "tst-missing-signing-certificate-attr",
            "no ESS signing-certificate attribute among the signed attributes; "
            "RFC 3161 section 2.4.1 requires a TimeStampToken to identify the "
            "certificate the TSA signed under, carried as either " +
            " or ".join(f"{name} [{oid_}]" for oid_, name
                        in ESS_SIGNING_CERTIFICATE_ATTRS.items()) +
            ". Without it nothing in the signed data says WHICH certificate the "
            "signature belongs to. The TOKEN is wrong; nothing is missing from "
            "this checker")
    # Both forms at once is not a defect any clause names, so it is REPORTED.
    return ", ".join(ESS_SIGNING_CERTIFICATE_ATTRS[o] for o in present)


def _parse_signed_attrs(element) -> tuple[bytes, str, bytes]:
    """Return `(der_for_signing, content_type_oid, message_digest, ess_form)`.

    `ess_form` names which ESS signing-certificate attribute discharged
    `BV-029`. It is diagnostic text and has no path to a verdict.
    """
    # RFC 5652 section 5.4: the signature is over the DER of SignedAttributes as
    # a SET OF -- the [0] IMPLICIT identifier octet replaced by 0x31. ONE BYTE
    # is substituted; every content octet is the signer's, untouched.
    raw = element.raw
    signed_attrs_der = bytes([der.TAG_SET]) + raw[1:]

    seen: dict[str, bytes] = {}
    for attr in element.children:
        children = _seq(attr, "SignedAttribute", minimum=2, maximum=2)
        attr_type = _wrap("attribute.attrType",
                          lambda: der.oid(children[0], "attribute.attrType"))
        values = children[1]
        if values.tag != der.TAG_SET:
            # ⚠, SPLIT HERE. **THE TOKEN IS WRONG.** RFC 5652 section 5.3
            # defines `Attribute.attrValues` as `SET OF AttributeValue`; a
            # `SignedAttribute` whose values field carries any other tag is
            # malformed on its face, and NOTHING about it is a limit of this
            # build. *Until now it raised `tst-attr-malformed`, which is
            # `_SHORT` -- so a token that violates the CMS syntax returned
            # `UNATTESTED`, under-claiming a defect we could see plainly.*
            #
            # ***THIRD GENERATION OF ONE SHAPE:*** `rfc3161-token-malformed`
            # spanned two classes, then `tst-attr-malformed`'s value COUNT did,
            # and now its value TYPE. **§4's enumeration of the residual is the
            # sweep that is meant to find the fourth, rather than the next
            # repair finding it.**
            raise Rfc3161Error(
                "tst-attr-values-not-a-set",
                f"attribute {attr_type} carries attrValues under tag "
                f"0x{values.tag:02x}; RFC 5652 section 5.3 defines attrValues as "
                "a SET OF AttributeValue, so this is malformed on its face. The "
                "TOKEN is wrong; this is not a limit of this checker")
        if len(values.children) != 1:
            # ⚠, SPLIT Until now one code covered both
            # classes: an attribute the standard PINS to one value and one it
            # leaves open. **The first is the token's defect, the second is our
            # limit**, and `BV-028` turns on exactly that line -- a caller
            # cannot tell them apart from one code any more than from one bool.
            section = SINGLE_VALUE_REQUIRED.get(attr_type)
            if section is not None:
                raise Rfc3161Error(
                    "tst-attr-single-value-required",
                    f"attribute {attr_type} carries {len(values.children)} "
                    f"values; {section} requires this attribute to carry exactly "
                    "one, notwithstanding that the syntax admits a SET OF. "
                    "The TOKEN is wrong; this is not a limit of this checker")
            raise Rfc3161Error(
                "tst-attr-malformed",
                f"attribute {attr_type} carries {len(values.children)} values; "
                "this checker reads single-valued attributes only, and a "
                "multi-valued one would leave WHICH value was meant undecided. "
                "CMS does not pin this attribute to one value, so THIS BUILD is "
                "short and nothing is asserted about the token")
        if attr_type in seen:
            raise Rfc3161Error("tst-duplicate-attr",
                               f"attribute {attr_type} appears more than once; "
                               "which copy the signature covers is undecidable")
        seen[attr_type] = values.children[0]

    if ID_ATTR_CONTENT_TYPE not in seen:
        raise Rfc3161Error("tst-missing-content-type-attr",
                           "no contentType among the signed attributes (RFC 5652 "
                           "section 11.1), so the signature does not say WHAT it signed")
    content_type = _wrap("contentType attribute",
                         lambda: der.oid(seen[ID_ATTR_CONTENT_TYPE], "contentType"))
    if ID_ATTR_MESSAGE_DIGEST not in seen:
        raise Rfc3161Error("tst-missing-message-digest-attr",
                           "no messageDigest among the signed attributes (RFC 5652 "
                           "section 11.2); without it the signature is not bound to "
                           "the eContent at all")
    message_digest = _wrap(
        "messageDigest attribute",
        lambda: der.octets(seen[ID_ATTR_MESSAGE_DIGEST], "messageDigest"))

    # ⚠ `BV-029`. **RFC 3161 section 2.4.1 REQUIRES the token to identify the
    # certificate it was signed under**, as a signed ESS attribute -- either
    # form. **A token carrying neither is missing a field its own standard makes
    # mandatory, which makes it a DEFECTIVE TOKEN and not a gap in this
    # checker.**
    #
    # *Found the only way it could be: `X-05` carried an artefact OpenSSL minted
    # under `cms -sign`, which omits the attribute. This build returned
    # `token-verified` on it and OpenSSL's own RFC 3161 verifier returned
    # FAILED, over this one field.* **Every fixture on both sides of this
    # checker happened to carry the attribute, so no fixture could reveal that
    # it was never required, and no mutation could either -- a campaign varies
    # the CODE and holds the FIXTURE.**
    ess_description = _require_ess_signing_certificate(seen)
    return signed_attrs_der, content_type, message_digest, ess_description


def parse_token(data: bytes, *, limits: der.Limits) -> TimeStampToken:
    """Parse a `TimeStampToken`. Raises `Rfc3161Error`. **Verifies nothing.**

    `limits` is keyword-only and required — `BV-023`.
    """
    try:
        root = der.parse(data, limits=limits)
    except der.DerError as exc:
        raise _from_der_error(exc, "", limits) from None

    # --- ContentInfo ---------------------------------------------------
    ci = _seq(root, "ContentInfo", minimum=2, maximum=2)
    content_type = _wrap("ContentInfo.contentType",
                         lambda: der.oid(ci[0], "ContentInfo.contentType"))
    if content_type != ID_SIGNED_DATA:
        raise Rfc3161Error("tst-not-signed-data",
                           f"ContentInfo carries {content_type}; a TimeStampToken is "
                           f"a CMS SignedData ({ID_SIGNED_DATA})")
    if ci[1].tag != _CONTEXT_0_CONSTRUCTED or len(ci[1].children) != 1:
        raise Rfc3161Error("tst-not-content-info",
                           "ContentInfo.content is not a single [0] EXPLICIT element")

    # --- SignedData -----------------------------------------------------
    sd = _seq(ci[1].children[0], "SignedData", minimum=4, maximum=6)
    version = _wrap("SignedData.version",
                    lambda: der.integer(sd[0], "SignedData.version"))
    if version not in (1, 3, 4, 5):
        raise Rfc3161Error("tst-signed-data-version",
                           f"SignedData version {version} is not one RFC 5652 defines")
    if sd[1].tag != der.TAG_SET:
        raise Rfc3161Error("tst-structure", "SignedData.digestAlgorithms is not a SET")
    # RFC 5652 §5.1. READ, not enforced: the specification makes membership a
    # SHOULD ("implementations MAY fail to validate signatures that use a digest
    # algorithm that is not included in this set"), so a token whose SET omits
    # its own signer's algorithm is REPORTED by the checker and refused by
    # nobody here. *A SHOULD enforced as a MUST is a wire format invented by
    # the consumer.*
    signed_data_digest_algorithms = tuple(
        _algorithm_id(child, "SignedData.digestAlgorithms[]")
        for child in sd[1].children)

    encap = sd[2]
    tail = list(sd[3:])
    certificates_present = bool(tail) and tail[0].tag == _CONTEXT_0_CONSTRUCTED
    if certificates_present:
        tail.pop(0)
    if tail and tail[0].tag == _CONTEXT_1_CONSTRUCTED:      # crls
        tail.pop(0)
    if len(tail) != 1 or tail[0].tag != der.TAG_SET:
        raise Rfc3161Error("tst-structure",
                           "SignedData does not end in a SET OF SignerInfo")
    signer_infos = tail[0]

    # --- EncapsulatedContentInfo ---------------------------------------
    enc = _seq(encap, "EncapsulatedContentInfo", minimum=1, maximum=2)
    econtent_type = _wrap("eContentType", lambda: der.oid(enc[0], "eContentType"))
    if econtent_type != ID_CT_TST_INFO:
        raise Rfc3161Error("tst-wrong-econtent-type",
                           f"eContentType is {econtent_type}; a TimeStampToken "
                           f"encapsulates id-ct-TSTInfo ({ID_CT_TST_INFO})")
    if len(enc) != 2 or enc[1].tag != _CONTEXT_0_CONSTRUCTED or not enc[1].children:
        raise Rfc3161Error("tst-no-econtent",
                           "the token carries no eContent. RFC 3161's token is not "
                           "detached: without the TSTInfo there is nothing to check "
                           "the messageImprint against")
    econtent = _wrap("eContent", lambda: der.octets(enc[1].children[0], "eContent"))

    # --- SignerInfo ------------------------------------------------------
    if len(signer_infos.children) != 1:
        raise Rfc3161Error(
            "tst-signer-count",
            f"{len(signer_infos.children)} SignerInfo(s); this checker reads "
            "exactly one, because 'the token verifies' would otherwise not say "
            "WHICH signer it verified under")
    si = _seq(signer_infos.children[0], "SignerInfo", minimum=5, maximum=7)
    si_version = _wrap("SignerInfo.version",
                       lambda: der.integer(si[0], "SignerInfo.version"))
    if si_version not in (1, 3):
        raise Rfc3161Error("tst-signer-version",
                           f"SignerInfo version {si_version}; RFC 5652 defines 1 and 3")
    sid = si[1]
    sid_description = (f"subjectKeyIdentifier ({len(sid.content)} bytes)"
                       if sid.tag == _CONTEXT_0_PRIMITIVE
                       else f"tag 0x{sid.tag:02x}")
    # ⚠ RFC 5652 §5.3. **READ, not required.** The one gate left is whether
    # THIS BUILD performs the algorithm the signer named -- a fact about the
    # checker, which is why its refusal says "this checker implements" and
    # names the whole declared set rather than a single constant.
    digest_algorithm, digest_params_present = _algorithm_id_full(
        si[2], "SignerInfo.digestAlgorithm")
    if digest_algorithm not in DIGEST_ALGORITHMS:
        raise Rfc3161Error(
            "tst-digest-algorithm-unsupported",
            f"SignerInfo digests under {digest_algorithm}; this checker "
            f"implements " + ", ".join(
                f"{name} ({o})" for o, (name, _) in DIGEST_ALGORITHMS.items()))

    rest = list(si[3:])
    if not rest or rest[0].tag != _CONTEXT_0_CONSTRUCTED:
        raise Rfc3161Error(
            "tst-no-signed-attrs",
            "the SignerInfo carries no signedAttrs. RFC 3161 requires them, and "
            "without them the signature would be over the TSTInfo alone -- so "
            "nothing would bind the signature to its own contentType")
    (signed_attrs_der, attr_content_type, attr_message_digest,
     ess_signing_certificate) = _parse_signed_attrs(rest.pop(0))
    if attr_content_type != econtent_type:
        raise Rfc3161Error(
            "tst-content-type-attr-mismatch",
            f"the signed contentType attribute says {attr_content_type} and the "
            f"encapsulated content is {econtent_type}. The signature covers the "
            "attribute, so trusting the unsigned side would let a relayer "
            "re-label what was signed")

    if len(rest) < 2:
        raise Rfc3161Error("tst-structure",
                           "SignerInfo lacks signatureAlgorithm or signature")
    (signature_algorithm, _sig_params_present,
     _sig_params_null) = _algorithm_id_params(rest[0],
                                              "SignerInfo.signatureAlgorithm")
    if signature_algorithm not in ADMITTED_SIGNATURE_ALGORITHMS:
        # ⚠ THE LIMITATION IS NARROWED, NEVER REMOVED. Ed25519
        # (RFC 8419), RSASSA-PKCS1-v1_5 with SHA-2 (RFC 8017 A.2.4) and ECDSA
        # with SHA-256 over P-256 (RFC 5758 §3.2) are implemented, each from its
        # specification, standard library only. **DSA, ECDSA over other curves
        # or digests, and everything else** are refused HERE, by name, rather
        # than mis-verified or silently skipped — this build being short, never
        # a finding against the token.
        #
        # *Refusing by name is the honest outcome: the alternative is a checker
        # that reports "does not verify" for a token it never attempted, which
        # is ERR-P3-008's distinction inverted inside a single function.*
        raise Rfc3161Error(
            "tst-signature-algorithm-unsupported",
            f"the token is signed under {signature_algorithm}; this checker "
            f"implements {sorted(ADMITTED_SIGNATURE_ALGORITHMS)}. A TSA signing "
            "under anything else reaches this refusal, and that is a limitation "
            "of this pack rather than a finding against the token")
    # ⚠ RFC 8419 §3.1, and it is a CONFORMANCE check on the token rather than a
    # limitation of this checker. It runs HERE because it needs both algorithms
    # and `signatureAlgorithm` follows `signedAttrs` in a `SignerInfo`.
    #
    # *The order matters and is deliberate: "does this build perform that
    # digest" is asked at si[2], in the token's own field order, so a
    # `digestAlgorithm` this checker lacks is named as OUR gap before the
    # pairing rule can rename it as the token's defect. Both codes stay
    # reachable and each keeps naming a different party's fact.*
    # ⚠⚠ **`rsaEncryption`, landing B.** It takes no row in
    # `SIGNATURE_DIGEST_REQUIREMENTS`, so the pairing check below passes over it
    # by design -- RFC 3370 §3.2 says the identifier applies *"regardless of the
    # message digest algorithm employed"*, and inventing a pairing here would
    # manufacture a conformance requirement no RFC states. Its two rules are
    # these, and they name DIFFERENT parties' facts (`BV-028`).
    if signature_algorithm == ID_RSA_ENCRYPTION:
        # (i) THE TOKEN's defect. RFC 3370 §3.2 fixes the parameters at NULL.
        if _sig_params_present and not _sig_params_null:
            raise Rfc3161Error(
                "tst-signature-algorithm-parameters-invalid",
                "the SignerInfo signs under rsaEncryption and carries a "
                "parameters field that is neither NULL nor absent; RFC 3370 "
                "section 3.2 fixes it at NULL. This checker reads the field it "
                "was given and this is a finding against the TOKEN, not a "
                "limit of this build")
        # (ii) OUR gap. The hash is READ from the SignerInfo, per RFC 3370
        # section 3.2, and then it has to be one we can actually build a
        # `DigestInfo` for. `id-sha224` reaches here: `DIGEST_ALGORITHMS`
        # performs it, `rsa_pkcs1` has no prefix for it, and that is OUR
        # shortfall and never the token's.
        if digest_algorithm not in RSA_ENCRYPTION_DIGESTS:
            raise Rfc3161Error(
                "tst-digest-algorithm-unsupported",
                f"the token signs under rsaEncryption and digests under "
                f"{digest_algorithm}; this build performs RSASSA-PKCS1-v1_5 "
                f"over {sorted(RSA_ENCRYPTION_DIGESTS)} only. RFC 3370 section "
                "3.2 permits the pairing; THIS BUILD is short, and that is not "
                "a finding against the token")

    # ⚠⚠ **THE POLICY ARM** (`BV-028`). It runs before the conformance arm and
    # the two can never both fire: the tables are disjoint by construction.
    # **A mispaired RSA token is still REFUSED** — only the code and the class
    # change, and the refusal now names this checker rather than the record.
    declined = RSA_DIGEST_PAIRING_POLICY.get(signature_algorithm)
    if declined is not None and digest_algorithm != declined:
        raise Rfc3161Error(
            "tst-digest-algorithm-pairing-declined",
            f"the token signs under {signature_algorithm} and digests under "
            f"{digest_algorithm}. This checker verifies that identifier only "
            f"against {declined}, and declines the pairing it was given. No "
            "RFC this build cites requires that pairing — RFC 3370 section 3.2 "
            "says the RSA identifier applies regardless of the message digest "
            "algorithm employed — so this is a limit of THIS PACK and not a "
            "finding against the token")

    required = SIGNATURE_DIGEST_REQUIREMENTS.get(signature_algorithm)
    if required is not None and digest_algorithm != required[0]:
        raise Rfc3161Error(
            "tst-digest-algorithm-not-permitted",
            f"the token signs under {signature_algorithm} and digests under "
            f"{digest_algorithm}; {required[1]} requires {required[0]} with that "
            "signature algorithm. This checker performs the digest it was given "
            "and this is a finding against the TOKEN, not a limit of this build")
    signature = _wrap("SignerInfo.signature",
                      lambda: der.octets(rest[1], "SignerInfo.signature"))

    tst_info = _parse_tst_info(econtent, limits)
    return TimeStampToken(
        tst_info=tst_info, econtent=econtent, signed_attrs_der=signed_attrs_der,
        signed_attr_content_type=attr_content_type,
        signed_attr_message_digest=attr_message_digest,
        digest_algorithm=digest_algorithm,
        digest_algorithm_parameters_present=digest_params_present,
        signed_data_digest_algorithms=signed_data_digest_algorithms,
        signature_algorithm=signature_algorithm, signature=signature,
        sid_description=sid_description,
        certificates_present=certificates_present,
        ess_signing_certificate=ess_signing_certificate)
