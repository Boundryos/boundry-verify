"""The `rfc3161` token checker — STOP-B.

**Built from RFC 3161, RFC 5652 and RFC 8419 alone. `substrate/witness/` has not
been opened.** *If the kernel's client and this checker disagree, that
disagreement is the finding the separation exists to produce.*

## ⚠ It is REGISTERED, never built in. `BV-019` is not relaxed.

**Nothing here installs itself.** `make_verifier` returns a callable that an
operator puts into their own `token_verifiers` mapping under whatever kind they
choose. *One real kind existing is exactly when it becomes tempting to make it
the default, and a default checker is a verifier deciding on the operator's
behalf which witnesses it will believe.*

**And `token-kind-unverifiable` must stay reachable.** A kind with no checker is
still `UNATTESTED` under its own code — ***the moment one kind works is the
moment it becomes tempting to treat an unverifiable kind as an error rather than
as an honest absence.***

## What it establishes, and it is narrower than "the token is good"

1. **The `messageImprint` equals `ERR-P3-004`'s digest** — the value passed in,
   **recomputed by the caller from the checkpoint statement**, never read from
   the token's own account of itself.
2. **The signature verifies under the ANCHORED key** — `BV-010`. The anchored
   key material is the only key this function can reach; there is no parameter
   through which a bundle-supplied one could arrive.
3. **The signed `messageDigest` attribute covers the `eContent`**, so the
   signature is bound to the TSTInfo rather than merely accompanying it.
4. **The ESS signing-certificate attribute is PRESENT** — `BV-029`, RFC 3161
   §2.4.1. ***Presence, and nothing more:*** this checker builds no chain, so
   the attribute's contents are compared to nothing.

## ⚠ — `BV-029`, AND WHERE IT CAME FROM

**Until this pack the checker did not require the ESS attribute and attested a
token with none.** *No fixture could have shown that — every artefact on both
sides of this checker carried it — and no mutation could either, because a
campaign varies the code and holds the fixture.* **It was found by `X-05`, on an
artefact minted by OpenSSL, which our verifier called `token-verified` and
OpenSSL's own RFC 3161 verifier called FAILED.** ***Its absence is `REFUTED`:
the token is wrong, and nothing is missing from this checker.***

## ⚠ REPAIRED — TWO PLACES THAT ASSUMED SHA-256

**1 · The `messageDigest` attribute is now hashed under the algorithm the
token's `SignerInfo` DECLARES** (RFC 5652 §5.3, §5.4), not under a constant.
*The first interoperation run refused a conforming Ed25519 token because this
checker required `id-sha256` while RFC 8419 §3.1 requires `id-sha512` of exactly
the signatures it accepts.* **As built it could not verify any conforming token
of the only kind it took.**

**2 · The anchor's `key_material` is REDUCED under the format it declares**
(`key_forms`), rather than accepted only in one encoding. `BV-011` as corrected
 compares KEYS and not ENCODINGS, **and the same reduction has to
happen here or an anchor and a bundle carrying one key in two representations
would agree at the comparison and disagree at the check.**

> ***A checker that reduces for the comparison and not for the verification has
> moved the disagreement rather than removed it.***

**`genTime` is REPORTED, NEVER JUDGED**, and it travels as a FINDING — which by
 cannot alter a verdict. *A verifier does not know what time it is in any
sense a record can rely on, and a checker that rejected a token for being too
old would have substituted its own clock for evidence.*

## What it does NOT establish, and never could from a token alone

- **that the TSA's clock was right.** A timestamp is a witness's assertion; the
  anchor says whose assertion it is, not that it is true.
- **that the anchored key is the one the TSA uses today.** An anchor is a
  provisioning decision, not a live lookup.
- **anything about certificates.** RFC 3161 tokens usually carry a chain; this
  checker **does not build or validate one**, because a path validator written
  from inference is a second wire format invented by the consumer. The anchor
  supplies the key directly and the chain is ignored — *stated, so nobody reads
  a verified token as a validated chain.*
"""

from __future__ import annotations

from dataclasses import dataclass

from . import der, key_forms, rfc3161, witness
from .ed25519 import verify as ed25519_verify
from . import ecdsa_p256, rsa_pkcs1

__all__ = ["make_verifier", "CAUSES", "ANCHOR_FORMAT", "ANCHOR_FORMATS",
           "CAUSE_CLASSES", "PARSE_REFUSAL_CLASSES", "RULED_BY_NAME",
           "Standard", "EvidenceFailed", "BuildLimit", "Dispatch",
           "NotARefusal", "Unresolved", "class_of",
           "CAUSE_CITATIONS", "REFUSAL_CITATIONS", "WAIVED"]

#: The key this checker ultimately verifies under: RFC 8419's Ed25519, raw 32
#: bytes. **Every accepted anchor is REDUCED to this**, which is why it is still
#: one value while the accepted representations are several.
ANCHOR_FORMAT = "ed25519-raw"

#: The anchor representations this checker can reduce. **DECLARED, not
#: provisioned** — a published fact about this build.
ANCHOR_FORMATS = key_forms.REDUCIBLE_FORMATS

#: Every named cause this checker can report. **Each is shown reachable in
#: `selftest_p303_b.py`** -- made the reachability sweep the standard for
#: a refusal vocabulary, and a cause no input reaches is a comment.
#: ⚠ Which key kind each admitted signature algorithm requires. Keyed by NAME,
#: so `vocabulary_sweep` discovers no new subject.
_KIND_FOR_ALGORITHM = {
    rfc3161.ID_ED25519: key_forms.KIND_ED25519,
    rfc3161.ID_RSA_SHA256: key_forms.KIND_RSA,
    rfc3161.ID_RSA_SHA384: key_forms.KIND_RSA,
    rfc3161.ID_RSA_SHA512: key_forms.KIND_RSA,
    rfc3161.ID_ECDSA_SHA256: key_forms.KIND_EC,
    # ⚠ landing B. The kind is RSA, so the anchor-kind
    # matrix rules it exactly as the three `sha*WithRSAEncryption` rows are
    # ruled. Only the HASH is resolved differently -- see `_rsa_hash_name`.
    rfc3161.ID_RSA_ENCRYPTION: key_forms.KIND_RSA,
}

#: ⚠ The `ecdsa_p256` refusals that are facts about the TOKEN'S SIGNATURE, as
#: against the anchor's key. Landing A's lesson, applied before the crash.
_EC_SIGNATURE_FAULTS = frozenset({
    "ecdsa-r-out-of-range",
    "ecdsa-s-out-of-range",
})


def _ecdsa_sig_values(signature: bytes, limits) -> tuple:
    """`(r, s)` from `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`.
    RFC 3279 §2.2.3, parsed with canon's own bounded DER reader."""
    root = der.parse(signature, limits=limits)
    der.expect(root, der.TAG_SEQUENCE, "ECDSA-Sig-Value")
    fields = der.fields(root, "ECDSA-Sig-Value", minimum=2, maximum=2)
    return (der.integer(fields[0], "ECDSA-Sig-Value.r"),
            der.integer(fields[1], "ECDSA-Sig-Value.s"))


#: ⚠⚠ The `rsa_pkcs1` refusals that are facts about the TOKEN'S SIGNATURE rather
#: than about the anchor's key. Keyed by NAME for the `ROWS` reason below.
_RSA_SIGNATURE_FAULTS = frozenset({
    "rsa-signature-length",
    "rsa-signature-out-of-range",
})

#: ⚠ Which hash each admitted RSA OID names, RFC 8017 A.2.4. Keyed by NAME, so
#: `vocabulary_sweep` discovers no new subject and `ROWS` does not move.
_RSA_HASH_FOR = {
    rfc3161.ID_RSA_SHA256: "sha256",
    rfc3161.ID_RSA_SHA384: "sha384",
    rfc3161.ID_RSA_SHA512: "sha512",
}

#: ⚠ The hash names this build can perform an RSA verification under, keyed by
#: the DIGEST identifier the token declares. **DERIVED from `_RSA_HASH_FOR`'s own
#: values** against `rfc3161`'s digest identifiers, so the two
#: cannot disagree and no third list exists to drift.
_RSA_HASH_FOR_DIGEST = {
    rfc3161.ID_SHA256: "sha256",
    rfc3161.ID_SHA384: "sha384",
    rfc3161.ID_SHA512: "sha512",
}


def _reduced_key_size(material) -> str:
    """The reduced key's size **in its own kind's unit, derived from the value.**

    ⚠⚠ **`CF-CONF-002`, FOUND BY THE FIRST OPENSSL TOKEN THAT EVER VERIFIED.**
    The success finding below used to read
    `f"a {len(anchor_key)}-byte Ed25519 public key"`. `anchor_key` is the
    REDUCED value, and landing A made that a 2-tuple for RSA
    (`modulus, exponent`) and landing B a 2-tuple for EC (`qx, qy`) -- so an
    EC anchor was reported as ***"a 2-byte Ed25519 public key"***: wrong
    algorithm, and a length that measured the tuple. **The verdict was right
    and the evidence it gave for it was false**, which is the whole of
    `CF-CONF-002`, and it was unreachable until an RSA or EC token could reach
    the success path at all.

    The size is derived from the material's SHAPE, not written out per kind
raw bytes are measured in bytes, and a reduced integer pair
    in the bits of its first member -- the RSA modulus, the EC x-coordinate.
    **The KIND is not guessed here either**; it is the tag `reduce_to_key`
    returned.
    """
    if isinstance(material, (bytes, bytearray)):
        return f"{len(material)}-byte"
    return f"{material[0].bit_length()}-bit"


def _rsa_hash_name(parsed) -> str | None:
    """The hash an RSA `SignerInfo` is to be verified under.

    ⚠⚠ **TWO CONVENTIONS, AND THE RFC DECIDES WHICH.** A
    `sha*WithRSAEncryption` identifier names its own hash, so the hash comes
    from the SIGNATURE algorithm. `rsaEncryption` names none -- RFC 3370 §3.2
    says it identifies an RSA PKCS#1 v1.5 signature *"regardless of the message
    digest algorithm employed"* -- so the hash is READ from the `SignerInfo`'s
    `digestAlgorithm`, which `rfc3161.parse_token` has already restricted to
    `RSA_ENCRYPTION_DIGESTS`. *The binding is not taken on trust: the
    `DigestInfo` inside the signature carries the hash's own OID, so an EMSA
    comparison against the wrong hash fails to verify.*
    """
    if parsed.signature_algorithm == rfc3161.ID_RSA_ENCRYPTION:
        return _RSA_HASH_FOR_DIGEST.get(parsed.digest_algorithm)
    return _RSA_HASH_FOR.get(parsed.signature_algorithm)

CAUSES = (
    "rfc3161-anchor-format-unsupported",
    "rfc3161-anchor-key-not-reduced",
    "rfc3161-anchor-kind-mismatch",
    "rfc3161-token-malformed",
    "rfc3161-token-not-evaluable",
    "rfc3161-imprint-mismatch",
    "rfc3161-message-digest-mismatch",
    "rfc3161-signature-does-not-verify",
    "rfc3161-verified",
)

_SHORT = witness.TOKEN_REFUSED_CHECKER_SHORT
_DEFECT = witness.TOKEN_REFUSED_TOKEN_DEFECT

# ---------------------------------------------------------------------------
# ⚠ — THE CITATION MECHANISM. **THE CLASS IS DERIVED FROM THE
# CITATION; IT IS NOT DECLARED BESIDE IT.**
# ---------------------------------------------------------------------------
#
# A ruling asked for every refusal code to carry BOTH its class AND a citation,
# with the relation between them asserted. ***THIS IMPLEMENTS THE INTENT AND NOT
# THE SHAPE, AND THE DIFFERENCE IS THE WHOLE VALUE OF IT.***
#
# **Two fields with an asserted relation means deciding, from free text, whether
# a citation "names a standard" or "names this build" — a regex over prose.**
# *That is the thing that rots: people write prose that satisfies the regex.*
#
# ***SO THERE IS ONE FIELD. The citation is a TYPE, and the class is a FUNCTION
# of that type.*** **Nothing can disagree with anything, because there is only
# one place the class comes from.** *Choosing the citation IS choosing the class,
# at the moment the code is created, which is exactly what wanted.*


@dataclass(frozen=True)
class Standard:
    """A clause of a standard THE TOKEN violates. **Implies `_DEFECT`.**

    `document` and `section` are separate REQUIRED fields, deliberately: a
    build limit cannot fill them honestly, and *"X.690 structural requirements"*
    is not expressible. **The type is the discipline; there is no regex.**
    """

    document: str
    section: str
    requirement: str


@dataclass(frozen=True)
class EvidenceFailed:
    """A substantive check RAN on well-formed evidence and it did not hold.
    **Implies `_DEFECT`.**

    ⚠ **'s table has no row for this and it needs one.** *It says
    `_DEFECT` must cite "a clause of a standard the token violates" — but
    `rfc3161-imprint-mismatch` violates no clause: the token may be a perfectly
    good token about something else, as its own refusal says.* **Three of this
    checker's `_DEFECT` causes are of this kind.**

    ***Forcing them into `Standard` would have meant inventing a clause number
    to satisfy the checker, which is the rot the mechanism exists to prevent.***
    Both kinds are `_DEFECT` because `BV-028`'s line is *evidence supplied and
    failed* against *the check never ran* — and both of these are the former.
    """

    checked: str


@dataclass(frozen=True)
class BuildLimit:
    """**The check never ran. Implies `_SHORT`.**

    Either this build implements no such thing, or the input it needed was not
    usable evidence about the record. *Nothing is asserted about the token
    either way, which is `BV-028` exactly.*
    """

    what: str


@dataclass(frozen=True)
class Dispatch:
    """Not a leaf refusal: it REPORTS the class of a refusal raised below it.

    `rfc3161-token-malformed` and `rfc3161-token-not-evaluable` are the two arms
    of one dispatch over `REFUSAL_CITATIONS`. **Their citation IS the underlying
    code's**, so they cannot carry one of their own — and the mechanism found
    that rather than being told it.
    """

    carries: str
    frm: str


@dataclass(frozen=True)
class NotARefusal:
    """The success cause. Carries `TOKEN_VERIFIED` and cites nothing."""


@dataclass(frozen=True)
class Unresolved:
    """⚠ **NO HONEST CITATION EXISTS FOR THIS CODE YET.**

    ***This is the mechanism REPORTING rather than passing.*** A code reaches
    this state when its stated reason cannot be written as a clause of a
    standard, as a check that ran, or as a limit of this build — **which is the
    signature of a code whose class was assigned by hand without anyone writing
    down why.** *That is the family is trying to close, caught at
    import instead of by the next repair.*

    **It carries the finding it is reported under and the class it currently
    has, so the waiver is never silent.** `WAIVED` below is asserted against a
    published list; **growing it requires editing a line that says what it is.**
    """

    finding: str
    current_class: str
    why_no_citation: str


#: The class each citation kind implies. **`class_of` is the ONLY place a class
#: is decided**, which is what makes "the relation" unnecessary rather than
#: asserted.
def class_of(citation):
    """The refusal class this citation implies. **One function, one source.**"""
    if isinstance(citation, (Standard, EvidenceFailed)):
        return _DEFECT
    if isinstance(citation, BuildLimit):
        return _SHORT
    if isinstance(citation, Dispatch):
        return citation.carries
    if isinstance(citation, NotARefusal):
        return witness.TOKEN_VERIFIED
    if isinstance(citation, Unresolved):
        return citation.current_class
    raise TypeError(f"not a citation: {citation!r}")

#: ⚠ **EVERY CAUSE, WITH ITS CITATION. The class is DERIVED below.**
CAUSE_CITATIONS = {
    "rfc3161-anchor-format-unsupported": BuildLimit(
        "this build holds no reducer for the representation the anchor "
        "declares; the anchor is the operator's provisioning and nothing was "
        "learned about the record"),
    # ⚠⚠ landing A. **A KIND MISMATCH IS NOT A FAILED VERIFICATION.**
    # The anchor is the operator's provisioning; a token signed under RSA and an
    # anchor carrying an Ed25519 key (or the reverse) tells us nothing whatever
    # about the record, so attempting the check and reporting "does not verify"
    # would name the WRONG PARTY'S FACT. `BV-028`, at the algorithm layer.
    "rfc3161-anchor-kind-mismatch": BuildLimit(
        "the token's signature algorithm and the anchor's key are different "
        "kinds; the anchor is the operator's provisioning and nothing was "
        "learned about the record"),
    "rfc3161-anchor-key-not-reduced": BuildLimit(
        "the anchor's material would not reduce to the key it denotes. An "
        "anchor is the OPERATOR's provisioning, never the record's evidence, "
        "so nothing whatever was learned about the record (BV-028; ruled by "
        "name at R-39, correcting an earlier reading that called it the "
        "anchor's defect)"),
    "rfc3161-token-malformed": Dispatch(_DEFECT, "REFUSAL_CITATIONS"),
    "rfc3161-token-not-evaluable": Dispatch(_SHORT, "REFUSAL_CITATIONS"),
    "rfc3161-imprint-mismatch": EvidenceFailed(
        "the token's messageImprint was compared to the digest the caller "
        "recomputed from the checkpoint statement (ERR-P3-004) and differed. "
        "It may be a perfectly good token about something else, which is why "
        "this cites no clause"),
    "rfc3161-message-digest-mismatch": EvidenceFailed(
        "the signed messageDigest attribute was recomputed over the eContent "
        "under the digestAlgorithm the token declares (RFC 5652 section 5.4) "
        "and differed, so the signature does not reach the TSTInfo"),
    "rfc3161-signature-does-not-verify": EvidenceFailed(
        "the signedAttrs were checked under the ANCHORED key (BV-010) and the "
        "signature did not verify"),
    "rfc3161-verified": NotARefusal(),
}

#: ⚠ **EVERY PARSE REFUSAL, WITH ITS CITATION. The class is DERIVED below.**
#:
#: *Each citation is taken from the refusal's own words or from the clause the
#: module was built against — not invented to satisfy the check.* **Where no
#: honest citation exists the entry is `Unresolved` and says so.**
REFUSAL_CITATIONS = {
    # --- the token violates a clause -------------------------------------
    "tst-not-content-info": Standard(
        "RFC 5652", "3",
        "ContentInfo carries its content as a single [0] EXPLICIT element"),
    "tst-not-signed-data": Standard(
        "RFC 3161", "2.4.2", "a TimeStampToken is a CMS SignedData"),
    "tst-signed-data-version": Standard(
        "RFC 5652", "5.1", "SignedData.version is one of the values CMS defines"),
    "tst-wrong-econtent-type": Standard(
        "RFC 3161", "2.4.2", "the encapsulated content type is id-ct-TSTInfo"),
    "tst-no-econtent": Standard(
        "RFC 3161", "2.4.2",
        "the token carries its TSTInfo; RFC 3161's token is not detached"),
    "tst-signer-version": Standard(
        "RFC 5652", "5.3", "SignerInfo.version is 1 or 3"),
    "tst-no-signed-attrs": Standard(
        "RFC 3161", "2.4.1",
        "the token carries signedAttrs; without them nothing binds the "
        "signature to its own contentType"),
    "tst-missing-content-type-attr": Standard(
        "RFC 5652", "11.1", "a content-type attribute is present"),
    "tst-content-type-attr-mismatch": Standard(
        "RFC 5652", "11.1",
        "the content-type attribute value matches the eContentType"),
    "tst-missing-message-digest-attr": Standard(
        "RFC 5652", "11.2", "a message-digest attribute is present"),
    "tst-missing-signing-certificate-attr": Standard(
        "RFC 3161", "2.4.1",
        "the token identifies the certificate the TSA signed under, as "
        "signingCertificate (RFC 2634) or signingCertificateV2 (RFC 5035). "
        "BV-029"),
    "tst-attr-values-not-a-set": Standard(
        "RFC 5652", "5.3", "attrValues is a SET OF AttributeValue"),
    "tst-attr-single-value-required": Standard(
        "RFC 5652", "11",
        "content-type, message-digest and signing-time each carry exactly one "
        "value, notwithstanding that the syntax admits a SET OF (11.1, 11.2, "
        "11.3; the per-attribute section is in rfc3161.SINGLE_VALUE_REQUIRED)"),
    "tst-info-version": Standard(
        "RFC 3161", "2.4.2", "TSTInfo.version is 1"),
    "tst-digest-algorithm-not-permitted": Standard(
        "RFC 8419", "3.1",
        "an Ed25519 CMS signature digests under id-sha512"),
    # ⚠ ONE CODE, SIX REMAINING SITES, ONE CITATION — AND IT GENERALISES.
    # **This is the mechanism's residual hole and it is named rather than
    # hidden.** *Post-split the six are: a DEFAULT encoded explicitly (X.690
    # 11.5); fields after TSTInfo's extensions; digestAlgorithms not a SET;
    # SignedData not ending in a SET OF SignerInfo; a SignerInfo lacking
    # signatureAlgorithm or signature; and any other DER error from `_seq` or
    # `_wrap`.* **All six are "these bytes are not a well-formed DER encoding of
    # the structure CMS and RFC 3161 define", which is one honest statement —
    # but a citation this general would also have covered the BOUND sites, which
    # were NOT that.**.
    "tst-structure": Standard(
        "X.690", "8-11",
        "the bytes are a well-formed DER encoding of the structure RFC 5652 "
        "and RFC 3161 define, with each field encoded exactly one way"),
    # --- the check never ran: THIS BUILD is short ------------------------
    "tst-digest-algorithm-unsupported": BuildLimit(
        "this checker performs the SHA-2 digests RFC 5754 section 2 names and "
        "no others"),
    # ⚠⚠ **THIS TEXT SAID "implements Ed25519 (1.3.101.112, RFC 8419) only; a
    # real TSA signing with RSA or ECDSA reaches this".** Landings A and B
    # implemented RSA and ECDSA and admits `rsaEncryption`, so the
    # sentence became false and is replaced. **No claim is made about what
    # authorities usually sign with**: this build's own admitted set is a fact
    # it can state, and a prevalence claim is not.
    "tst-signature-algorithm-unsupported": BuildLimit(
        "this checker implements the signature algorithms in "
        "rfc3161.ADMITTED_SIGNATURE_ALGORITHMS; a TSA signing under any other "
        "identifier reaches this"),
    # ⚠ landing B. The TOKEN's defect: RFC 3370 §3.2 leaves
    # rsaEncryption's parameters no latitude, unlike the absent-versus-NULL
    # question RFC 5754 §2 settles for SHA-2 DIGEST identifiers.
    # ⚠⚠ **`BV-028`, 15 September 2026. A `BuildLimit`, DELIBERATELY.** A
    # `Standard` requires a document AND a section, and *"a build limit cannot
    # fill them honestly"* — which is exactly the discipline that would have
    # caught this rule the day it was written. There is no section to give: no
    # RFC this module cites pairs an RSA signature OID with a digestAlgorithm.
    # **The type carries the finding.**
    "tst-digest-algorithm-pairing-declined": BuildLimit(
        "this checker verifies a sha*WithRSAEncryption signature only against "
        "the hash that identifier names, and declines any other pairing. No RFC "
        "cited by this build requires it; RFC 3370 section 3.2 says the RSA "
        "identifier applies regardless of the message digest algorithm "
        "employed. The pairing is THIS PACK's policy and the refusal says so"),
    "tst-signature-algorithm-parameters-invalid": Standard(
        "RFC 3370", "3.2",
        "the rsaEncryption algorithm identifier carries NULL parameters"),
    "tst-imprint-algorithm-unsupported": BuildLimit(
        "this checker implements SHA-256 only, which is what ERR-P3-004 "
        "attests under"),
    "tst-signer-count": BuildLimit(
        "this checker reads exactly one SignerInfo, because 'the token "
        "verifies' would otherwise not say WHICH signer it verified under"),
    "tst-attr-malformed": BuildLimit(
        "this checker reads single-valued attributes only; CMS does not pin "
        "this attribute to one value, so declining to guess WHICH value was "
        "meant is our limit and nothing is asserted about the token"),
    "tst-provisioned-bound-exceeded": BuildLimit(
        "the parse reached one of the operator's provisioned der.Limits and "
        "stopped. F-21, ruled at R-50 section 2: a bound WE chose being hit is "
        "not the token being wrong"),
    # --- ⚠ NO HONEST CITATION EXISTS. REPORTED, NOT PAPERED OVER. --------
    "tst-duplicate-attr": Unresolved(
        finding="F-23",
        current_class=_DEFECT,
        why_no_citation=(
            "the same attrType appears more than once. THIS CODE IS _DEFECT "
            "AND ITS OWN STATED REASON IS A DECIDABILITY LIMIT OF THIS BUILD "
            "-- 'which copy the signature covers is undecidable' -- which is "
            "the wording tst-attr-malformed uses to justify _SHORT. RFC 5652 "
            "section 5.3 defines SignedAttributes as a SET OF Attribute and "
            "does not forbid a repeated attrType; section 11 pins VALUE counts, "
            "not INSTANCE counts. No clause was found that the token violates, "
            "and inventing one to satisfy this check is the rot the mechanism "
            "exists to prevent. Reported, class NOT changed: the verifier "
            "moves for section 1 and section 2 only"),
    ),
}

#: ⚠ **THE CLASS MAPS, DERIVED. Nothing below is hand-maintained.**
#:
#: *`CAUSE_CLASSES` and `PARSE_REFUSAL_CLASSES` were two hand-written tables and
#: are now two comprehensions.* **A code cannot carry a class that disagrees
#: with its citation, because it no longer carries a class at all.**
CAUSE_CLASSES = {c: class_of(cit) for c, cit in CAUSE_CITATIONS.items()}
PARSE_REFUSAL_CLASSES = {c: class_of(cit) for c, cit in REFUSAL_CITATIONS.items()}

#: ⚠ **THE PUBLISHED WAIVER LIST.** *Every `Unresolved` citation, by code.*
#: **Growing it means editing a line that says what it is**, and the suites
#: assert its exact contents — so a code cannot join it quietly.
WAIVED = tuple(sorted(c for c, cit in REFUSAL_CITATIONS.items()
                      if isinstance(cit, Unresolved)))


#: The refusals ruled BY NAME — four, three, one
#: split, and one clause. **Recorded separately from the
#: table above so that what was ruled and what was DERIVED from the ruled
#: principle stay distinguishable.**
#:
#: ⚠ ** IS DISCHARGED HERE.** `tst-imprint-algorithm-unsupported` and
#: `tst-signer-count` were ratified `_SHORT` BY NAME and were
#: deliberately absent from this table until now: moved the
#: verifier for its own §1 and §2 and nothing else, so reported the gap
#: and left it visible rather than harmonising it on sight.
#: **A ruling required the register to say so, and the pack
#: that may move it. Their CLASSIFICATION does not change; only its provenance,
#: from derived-by-principle to ruled-by-name.**
#:
#: ***TWELVE entries, from eight.*** * said ten, and ten was right
#: for the pack that named only 's two. This pack also mints
#: `tst-attr-values-not-a-set` and
#: `tst-missing-signing-certificate-attr` (`BV-029`, minted ), and both
#: are ruled by name, so the count the absorbed pack stated is superseded by its
#: own successor's scope rather than missed.* **Recomputed by walking the table,
#: not counted by eye.**
RULED_BY_NAME = {
    "rfc3161-anchor-format-unsupported": _SHORT,
    "rfc3161-anchor-kind-mismatch": _SHORT,
    "rfc3161-anchor-key-not-reduced": _SHORT,
    "tst-digest-algorithm-unsupported": _SHORT,
    "tst-signature-algorithm-unsupported": _SHORT,
    # ⚠ `BV-028`: OUR limit, never the record's defect. It sits beside
    # `tst-digest-algorithm-unsupported` and NOT beside `not-permitted` below.
    "tst-digest-algorithm-pairing-declined": _SHORT,
    "tst-digest-algorithm-not-permitted": _DEFECT,
    "rfc3161-signature-does-not-verify": _DEFECT,
    # ⚠, and split **BOTH ARMS are
    # ruled**, which is what makes this a split rather than a new code beside an
    # old one: what remains under `tst-attr-malformed` is SHORT, and the
    # standard-pinned attributes are the token's defect.
    "tst-attr-malformed": _SHORT,
    "tst-attr-single-value-required": _DEFECT,
    # ⚠ Ruled BY NAME.
    "tst-imprint-algorithm-unsupported": _SHORT,
    "tst-signer-count": _SHORT,
    # ⚠: *"the TOKEN is wrong."* The residual
    # `tst-attr-malformed` above stays `_SHORT`, so **both arms of this split
    # carry their provenance too**, exactly 's two do.
    "tst-attr-values-not-a-set": _DEFECT,
    # ⚠ `BV-029`, minted and implemented **Ruled by
    # the clause rather than by a refusal table**, which is stronger: the
    # specification names the requirement and requires the checker to assert it.
    "tst-missing-signing-certificate-attr": _DEFECT,
    # ⚠: a bound the OPERATOR provisioned being
    # reached is `BV-028`'s "we are short", never the token being wrong.
    "tst-provisioned-bound-exceeded": _SHORT,
}

# ---------------------------------------------------------------------------
# ⚠ — THE IMPORT-TIME CHECKS. **THIS IS THE SWEEP.**
# ---------------------------------------------------------------------------
# *Four manual sweeps did not close the classification family. These run on
# every import, for ever, at no cost — and a code that cannot be cited stops the
# module rather than shipping a class nobody wrote down a reason for.*

_CITATION_TYPES = (Standard, EvidenceFailed, BuildLimit, Dispatch, NotARefusal,
                   Unresolved)

for _table, _name in ((CAUSE_CITATIONS, "CAUSE_CITATIONS"),
                      (REFUSAL_CITATIONS, "REFUSAL_CITATIONS")):
    for _code, _cit in _table.items():
        if not isinstance(_cit, _CITATION_TYPES):            # pragma: no cover
            raise RuntimeError(
                f"{_name}[{_code!r}] is not a citation: {_cit!r}. A bare string "
                "is exactly what this mechanism exists to refuse")
        if isinstance(_cit, Standard) and not (
                _cit.document.strip() and _cit.section.strip()
                and _cit.requirement.strip()):               # pragma: no cover
            raise RuntimeError(
                f"{_name}[{_code!r}]: a Standard citation needs a document, a "
                "SECTION and a requirement. A clause without a section is a "
                "gesture at a standard, not a citation")
        if isinstance(_cit, BuildLimit) and not _cit.what.strip():
            raise RuntimeError(                              # pragma: no cover
                f"{_name}[{_code!r}]: a BuildLimit must say what this build "
                "does not do")

# ⚠ The two dispatch arms must carry DIFFERENT classes and cover BOTH, or the
# split they implement has quietly become one thing again.
_dispatch = {c: cit for c, cit in CAUSE_CITATIONS.items()
             if isinstance(cit, Dispatch)}
if len(_dispatch) != 2 or {c.carries for c in _dispatch.values()} != {_DEFECT, _SHORT}:
    raise RuntimeError(                                      # pragma: no cover
        "the two dispatch causes must carry one class each and cover both; "
        f"got {[(c, cit.carries) for c, cit in _dispatch.items()]}")
if any(cit.frm != "REFUSAL_CITATIONS" for cit in _dispatch.values()):
    raise RuntimeError("a dispatch cause must name the table it dispatches from")

# ⚠ The waiver list is PUBLISHED and is asserted against `WAIVED`, so a code
# cannot acquire an `Unresolved` citation without the published tuple changing.
if WAIVED != ("tst-duplicate-attr",):                        # pragma: no cover
    raise RuntimeError(
        "the published waiver list has changed. Every Unresolved citation is a "
        "code whose class nobody can justify; it is reported by finding number "
        f"and never grown quietly. Now: {WAIVED}")

if set(CAUSE_CITATIONS) != set(CAUSES):                      # pragma: no cover
    raise RuntimeError(
        "CAUSE_CITATIONS must cite EXACTLY the declared causes; "
        f"uncited {sorted(set(CAUSES) - set(CAUSE_CITATIONS))}, "
        f"unknown {sorted(set(CAUSE_CITATIONS) - set(CAUSES))}")
if set(REFUSAL_CITATIONS) != set(rfc3161.REFUSALS):          # pragma: no cover
    raise RuntimeError(
        "REFUSAL_CITATIONS must cite EXACTLY rfc3161.REFUSALS; "
        f"uncited {sorted(set(rfc3161.REFUSALS) - set(REFUSAL_CITATIONS))}, "
        f"unknown {sorted(set(REFUSAL_CITATIONS) - set(rfc3161.REFUSALS))}")

# ---------------------------------------------------------------------------
# ⚠⚠ CONVERSION FIDELITY — **THE CHECK THAT MAKES THE SIXTH GENERATION
# IMPOSSIBLE RATHER THAN MERELY VISIBLE.**
# ---------------------------------------------------------------------------
#
# ***A CITATION PER CODE DOES NOT, BY ITSELF, CLOSE THE FAMILY — AND IS
# THE PROOF.*** **The ambiguity that produced generation four did not live in a
# code and did not live in a raise site: it arrived AT the raise site, inside a
# `der.DerError`.** *Before the split, `tst-structure` was reachable from both a
# clause violation and an operator's provisioned bound. Whoever wrote its
# citation would have written `Standard("X.690", ...)` — truthfully, for most of
# its sites — and the import check would have passed while three der codes
# carried the wrong class underneath it.*
#
# **So the LOWER layer is classified too** (`der.PROVISIONED_BOUND_REFUSALS`)
# **and the conversion is asserted to PRESERVE the class.** Every `der` refusal
# is driven through `rfc3161._from_der_error` here, at import:
#
#   * a PROVISIONED BOUND must land on a code whose citation is a `BuildLimit`;
#   * every other der refusal must land on a code whose citation is a `Standard`.
#
# ***Now a code cannot be reachable from both classes without stopping the
# module*** — which is the property wanted and which the citation
# field alone does not deliver.
_BOUND_SAMPLE = der.Limits(max_bytes=1, max_depth=1, max_elements=1)
for _dercode in der.REFUSALS:
    _converted = rfc3161._from_der_error(
        der.DerError(_dercode, "conversion-fidelity probe"), "", _BOUND_SAMPLE)
    _cit = REFUSAL_CITATIONS[_converted.code]
    _want = BuildLimit if _dercode in der.PROVISIONED_BOUND_REFUSALS else Standard
    if not isinstance(_cit, _want):                          # pragma: no cover
        raise RuntimeError(
            f"conversion fidelity: der refusal {_dercode!r} becomes "
            f"{_converted.code!r}, whose citation is {type(_cit).__name__} and "
            f"must be {_want.__name__}. A refusal that is the operator's "
            "provisioned bound has been flattened into one that says the token "
            "is wrong, or the reverse -- the fourth generation "
            "of this defect, and it is what this check exists to stop")
if set(PARSE_REFUSAL_CLASSES) != set(rfc3161.REFUSALS):      # pragma: no cover
    # ⚠ `C3`'s rule, third instance: the relation is asserted as a SET so the
    # next parser refusal fails here rather than passing quietly into REFUTED.
    raise RuntimeError(
        "PARSE_REFUSAL_CLASSES must classify EXACTLY rfc3161.REFUSALS; "
        f"unclassified {sorted(set(rfc3161.REFUSALS) - set(PARSE_REFUSAL_CLASSES))}, "
        f"unknown {sorted(set(PARSE_REFUSAL_CLASSES) - set(rfc3161.REFUSALS))}")
if set(RULED_BY_NAME) - (set(CAUSE_CLASSES) | set(PARSE_REFUSAL_CLASSES)):
    raise RuntimeError("RULED_BY_NAME names a code that does not exist")


def make_verifier(*, limits: der.Limits):
    """Build the `rfc3161` checker. **`limits` is provisioned, with no default.**

    `BV-023`: the bound on what will be parsed is the operator's decision, and
    a checker that could be built without one would be choosing it for them.
    """
    if not isinstance(limits, der.Limits):
        raise TypeError("limits must be a der.Limits; there is no default")

    def check(key_material: bytes, fmt: str, token: bytes,
              attested_digest: bytes):
        """A `witness.TokenVerifier`. Returns `(outcome_class, findings)`.

        **The first value is a member of `witness.TOKEN_CLASSES`, not a bool.**
        Every refusal below reads its class out of
        `CAUSE_CLASSES` rather than choosing one at the site, so the class of a
        cause is stated once, in a table that is checked for exhaustiveness,
        and cannot drift between the table and the branch.
        """
        def refuse(cause: str, *findings: str):
            """Refuse under `cause`, with the class the table gives it."""
            return CAUSE_CLASSES[cause], (f"{cause}: {findings[0]}",) + findings[1:]
        # ⚠ The anchor is REDUCED, not matched. `BV-011`'s correction reaches
        # here too: a format difference is not a key difference, and a checker
        # that only accepted one spelling would refuse the very key the
        # comparison had just declared identical.
        #
        # **Two causes, because they name two different parties' facts**
        # (`BV-028`): a representation this build holds no reducer for is OUR
        # gap; material that will not reduce under the format it declares is
        # the ANCHOR's defect, and an operator fixes them in different places.
        try:
            anchor_kind, anchor_key = key_forms.reduce_to_key(
                key_material, fmt, limits=limits)
        except key_forms.KeyFormError as exc:
            # ⚠ BOTH are `TOKEN_REFUSED_CHECKER_SHORT`, ruled BY NAME at
            # The second reads as the ANCHOR's defect and the
            # comment above said so -- but an anchor is the OPERATOR's
            # provisioning, never the record's evidence, so nothing whatever was
            # learned about the record either way. `BV-028` is right and the
            # earlier reading was wrong in the same direction it always is.
            if exc.code == "key-format-not-implemented":
                return refuse("rfc3161-anchor-format-unsupported",
                              f"the anchor declares {fmt!r}; "
                              f"{key_forms.describe()}, and it verifies under "
                              f"{ANCHOR_FORMAT!r} (RFC 8419)")
            return refuse("rfc3161-anchor-key-not-reduced",
                          f"the anchor declares {fmt!r} and its key material "
                          "could not be reduced to the key it denotes",
                          f"detail: {exc.code}: {exc.detail}")

        try:
            parsed = rfc3161.parse_token(token, limits=limits)
        except rfc3161.Rfc3161Error as exc:
            # ⚠ REPAIRED Until now every parse refusal
            # returned one cause and one bool, so `tst-structure` (the token is
            # malformed) and `tst-signature-algorithm-unsupported` (**every
            # real-world RSA or ECDSA timestamp authority**) left this function
            # indistinguishable and both became `REFUTED`. **That was.**
            #
            # The class now comes from `PARSE_REFUSAL_CLASSES`, which is checked
            # against `rfc3161.REFUSALS` for set equality at import.
            cause = ("rfc3161-token-not-evaluable"
                     if PARSE_REFUSAL_CLASSES[exc.code] is _SHORT
                     else "rfc3161-token-malformed")
            return refuse(cause, exc.code, f"detail: {exc.detail}")

        # (1) ERR-P3-004, RECOMPUTED. `attested_digest` is what the caller
        # derived from the checkpoint statement; the token's own imprint is
        # compared TO it and never taken FROM it.
        imprint = parsed.tst_info.message_imprint.hashed_message
        if imprint != attested_digest:
            return refuse("rfc3161-imprint-mismatch",
                          "the token stamps a digest other than the one this "
                          "checkpoint attests to; it may be a perfectly good "
                          "token about something else")

        # (3) the signature must be bound to the TSTInfo, not merely beside it.
        #
        # ⚠ **RFC 5652 §5.4: the digest is computed under the SIGNER's
        # `digestAlgorithm`**, which `parsed` READ from the token. `rfc3161`
        # refuses at parse time any identifier outside `DIGEST_ALGORITHMS`, so
        # `digest_for` cannot be `None` here; the invariant is stated rather
        # than re-tested, because a branch no input reaches is a comment.
        digest_fn = rfc3161.digest_for(parsed.digest_algorithm)
        if parsed.signed_attr_message_digest != digest_fn(parsed.econtent).digest():
            return refuse("rfc3161-message-digest-mismatch",
                          "the signed messageDigest attribute does not cover "
                          f"the eContent under {parsed.digest_algorithm}, which "
                          "the token declares, so the signature does not reach "
                          "the TSTInfo")

        # (2) BV-010. `key_material` is the ANCHOR's, and it is the only key
        # material in scope here.
        #
        # ⚠⚠ ** LANDING A: THE CHECK DISPATCHES ON THE TOKEN'S OWN
        # SIGNATURE ALGORITHM.** Until this landing `rfc3161.py` admitted one
        # algorithm, so this line could call Ed25519 unconditionally and be
        # right. It now admits four, and calling Ed25519 over an RSA signature
        # would report `does-not-verify` for a check never attempted — which is
        # `ERR-P3-008`'s distinction inverted inside one function.
        # ⚠⚠ **A THREE-KIND MATRIX LANDING B.** Every off-diagonal
        # cell of ed25519 × rsa × ec refuses and is never attempted: a kind
        # mismatch is the operator's provisioning and says nothing whatever
        # about the record (`BV-028`). Derived from the algorithm, never
        # inferred from a key's length.
        want_kind = _KIND_FOR_ALGORITHM.get(parsed.signature_algorithm)
        if want_kind is None:
            # `rfc3161`'s gate admitted an algorithm this table does not name —
            # the `AGREE-001` disagreement landing A found by crashing.
            return refuse("rfc3161-anchor-key-not-reduced",
                          f"the token signs under {parsed.signature_algorithm}, "
                          "which this build admits but maps to no key kind; "
                          "that is a disagreement inside this build")
        if anchor_kind != want_kind:
            return refuse("rfc3161-anchor-kind-mismatch",
                          f"the token signs under {parsed.signature_algorithm} "
                          f"(a {want_kind} algorithm) and the anchor carries a "
                          f"{anchor_kind} key; this is refused rather than "
                          "attempted, because a kind mismatch is the operator's "
                          "provisioning and says nothing about the record")
        if want_kind == key_forms.KIND_ED25519:
            ok = ed25519_verify(anchor_key, parsed.signed_attrs_der,
                                parsed.signature)
        elif want_kind == key_forms.KIND_EC:
            qx, qy = anchor_key
            try:
                r_int, s_int = _ecdsa_sig_values(parsed.signature, limits)
                ok = ecdsa_p256.verify(
                    qx, qy,
                    rfc3161.digest_for(parsed.digest_algorithm)(
                        parsed.signed_attrs_der).digest(),
                    r_int, s_int)
            except der.DerError as exc:
                return refuse("rfc3161-signature-does-not-verify",
                              f"the signature is not a well-formed "
                              f"ECDSA-Sig-Value (RFC 3279 §2.2.3): "
                              f"{exc.code}: {exc.detail}")
            except ecdsa_p256.EcdsaError as exc:
                if exc.code in _EC_SIGNATURE_FAULTS:
                    return refuse("rfc3161-signature-does-not-verify",
                                  f"the signature does not verify under the "
                                  f"ANCHORED key: {exc.code}: {exc.detail}")
                return refuse("rfc3161-anchor-key-not-reduced",
                              f"the anchor's EC key is not one this build will "
                              f"verify under: {exc.code}: {exc.detail}")
        else:
            modulus, exponent = anchor_key
            # ⚠⚠ **TWO TABLES THAT MUST AGREE, AND NOTHING ASKED** — `AGREE-001`,
            # found by the mutation run rather than by reading. `rfc3161`'s gate
            # decides WHICH OIDs are admitted; `_RSA_HASH_FOR` decides which hash
            # each one names. An OID admitted by the first and absent from the
            # second raised `KeyError` out of a verifier — a crash where a named
            # refusal belongs. The lookup is guarded and the disagreement is
            # reported as OUR gap, which is what it is.
            hash_name = _rsa_hash_name(parsed)
            if hash_name is None:
                return refuse("rfc3161-anchor-key-not-reduced",
                              f"the token signs under {parsed.signature_algorithm}, "
                              "which this build admits but names no hash for; that "
                              "is a disagreement between rfc3161's admitted set and "
                              "this module's hash table, and it is OUR defect")
            try:
                ok = rsa_pkcs1.verify(
                    modulus, exponent, hash_name,
                    parsed.signed_attrs_der, parsed.signature)
            except rsa_pkcs1.RsaError as exc:
                # ⚠⚠ **THE CODE DECIDES WHOSE FACT IT IS, AND THE FIRST SPELLING
                # OF THIS HANDLER GOT IT WRONG.** It mapped every `RsaError` to
                # the anchor, so an Ed25519-length signature carried under an RSA
                # label read as *the anchor's key is unusable* — which is false
                # and names the wrong party. `BV-028` is exactly this line.
                #
                # `rsa-signature-length` and `rsa-signature-out-of-range` are
                # facts about the TOKEN's signature: it was attempted and it did
                # not verify. The rest — the modulus policy, a bad exponent, a
                # hash this build lacks — are facts about the ANCHOR or about us.
                if exc.code in _RSA_SIGNATURE_FAULTS:
                    return refuse("rfc3161-signature-does-not-verify",
                                  f"the signature does not verify under the "
                                  f"ANCHORED key: {exc.code}: {exc.detail}")
                return refuse("rfc3161-anchor-key-not-reduced",
                              f"the anchor's RSA key is not one this build will "
                              f"verify under: {exc.code}: {exc.detail}")
        if not ok:
            return refuse("rfc3161-signature-does-not-verify",
                          "the signed attributes do not verify under the "
                          "ANCHORED key")

        info = parsed.tst_info
        digest_name = rfc3161.DIGEST_ALGORITHMS[parsed.digest_algorithm][0]
        # RFC 5652 §5.1 makes membership a SHOULD, so this is REPORTED and the
        # token is refused by nobody for it. `BV-024`: a finding cannot move a
        # verdict, which is what makes it safe to report a SHOULD at all.
        declared = (
            "the signer's digestAlgorithm is among SignedData.digestAlgorithms "
            "(RFC 5652 section 5.1)"
            if parsed.digest_algorithm in parsed.signed_data_digest_algorithms else
            f"NOTE: SignedData.digestAlgorithms "
            f"{list(parsed.signed_data_digest_algorithms)} does not include the "
            f"signer's {parsed.digest_algorithm}; RFC 5652 section 5.1 makes that "
            "a SHOULD, so it is reported and not refused")
        return witness.TOKEN_VERIFIED, (
            "rfc3161-verified",
            f"signature checked under {parsed.signature_algorithm} over "
            f"signedAttrs digested with {digest_name} "
            f"({parsed.digest_algorithm}), READ from the token's SignerInfo and "
            "required of it by RFC 8419 section 3.1",
            declared,
            ("the digestAlgorithm carried a parameters field; RFC 8419 section "
             "3.1 says absent and RFC 5754 section 2 says accept both. REPORTED, "
             "NOT JUDGED" if parsed.digest_algorithm_parameters_present else
             "the digestAlgorithm carried no parameters field (RFC 8419 section 3.1)"),
            f"the ESS signing-certificate attribute is present as "
            f"{parsed.ess_signing_certificate}, which RFC 3161 section 2.4.1 "
            "requires. PRESENCE ONLY: its contents were not parsed and "
            "were compared to no certificate",
            f"anchor reduced from {fmt!r} to a "
            f"{_reduced_key_size(anchor_key)} {anchor_kind} public key; "
            "reducing a representation is not validating it",
            f"genTime={info.gen_time} REPORTED, NOT JUDGED: this verifier has "
            "not compared it to any clock and holds no opinion on it",
            f"serial={info.serial_number} policy={info.policy}",
            f"tsa-name-present={info.tsa_present} accuracy-present="
            f"{info.accuracy_present} nonce={'yes' if info.nonce is not None else 'no'}",
            "no certificate chain was built or validated; the key came from the "
            "anchor",
        )

    return check
