"""The verifying key directory, alone.

The directory is how a verifier obtains a key WITHOUT asking the operator —
"since a verifier who must ask us has not verified anything independently".
"""

from __future__ import annotations

import hashlib
import json
import re

import base64
from typing import Any, Mapping

__all__ = ["KeyDirectoryError", "KeyDirectory", "parse_public_key", "EraKey",
           "Succession", "SUCCESSION_FORMS", "SUCCESSION_FORM_ID",
           "REQUIRED_ERA_FIELDS", "SHAPE_RULE", "SHAPE_REFUSALS"]

# Ed25519 SubjectPublicKeyInfo prefix (RFC 8410): SEQUENCE { SEQUENCE { OID
# 1.3.101.112 }, BIT STRING }. Fixed 12 bytes, then the 32-byte raw key.
_SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")

CURRENT, RETIRED, COMPROMISED = "current", "retired", "compromised"

# ── THE DIRECTORY'S SHAPE, REFUSED BY NAME ───────────────────────────────────
#
# The key-directory specification defines the shape in a TABLE — *"a
# mapping from era identifier to an entry"* with six named fields — and then
# every normative rule from KD-001 onward reasons about those fields as though
# they are already there. Nothing numbered says they must BE there.
#
# ⚠⚠ **MEASURED, AND THE VERIFIER CRASHED RATHER THAN REFUSED.** A directory
# missing one required field escaped as a bare `KeyError`, a non-mapping entry
# as a `TypeError`, and `python -m boundry_verify` printed a traceback into its
# own internals with NO `refused:` line at all. Every other malformation here —
# a bad status, an unparseable key, an ISO instant — is refused by name. The
# named checks were all DOWNSTREAM OF A BARE SUBSCRIPT.
#
# > ***THE VALIDATION A READER TRUSTS IS THE VALIDATION THAT RUNS FIRST. EVERY
# > CHECK BELOW A BARE SUBSCRIPT IS A CHECK ON INPUT THAT ALREADY GOT THROUGH.***
#
# `ERR-P4-002`: an implementation that cannot answer SAYS SO.

#: The fields 's table requires of every
#: entry. `valid_until` is NOT among them — §2 reads *"absent while the era is
#: current"*, so its absence is a state, never a fault.
REQUIRED_ERA_FIELDS = ("era", "algorithm", "public_key", "valid_from", "status")

#: ⚠ **`KD-014` WAS MINTED** as its own addendum on the
#: `KD-009`-`KD-013` precedent.
#: It governs **presence and type**. ⚠ **`KD-001` CONTINUES TO GOVERN
#: IMMUTABILITY** of `public_key`, `algorithm` and `valid_from` once
#: published, and the two are cited separately and NEVER merged — different
#: obligations, different refusals. Reusing `KD-001` here would also have
#: under-covered by two fields: it never names `era` or `status`.
#: Built as the placeholder `KD-<SHAPE>`, declared ONCE, so the later rename
#: was one line and no code string is spelled twice.
SHAPE_RULE = "KD-014"

#: What a shape refusal can say. Each is raised with the offending era named.
SHAPE_REFUSALS = (
    f"{SHAPE_RULE}-NOT-A-MAPPING",
    f"{SHAPE_RULE}-ENTRY-NOT-A-MAPPING",
    f"{SHAPE_RULE}-MISSING-FIELD",
)

# ── KD-009 (DRAFT): the succession, and WHAT THE SIGNATURE COVERS ────────────
#
# D6 requires rotation to be a new era key signed by the
# outgoing era key. A measurement found that EraKey had NO FIELD FOR IT: the format
# could not carry the evidence, so it was never a missing check.
#
# ⚠ THE SIGNED BYTES ARE NAMED, NOT INFERRED. `form_id` denotes the whole
# construction -- CP-003's discipline ("a verifier MUST NOT assume a
# construction; it MUST read this field and apply the named one") applied to a
# signature rather than a head. A signature whose covered material is inferred
# is BV-030's defect one layer earlier.
SUCCESSION_FORM_ID = "kd-succession-cf1"

#: What `kd-succession-cf1` denotes, exactly:
#:   * covered bytes = applied to the statement
#:     mapping BELOW, whole, with no field omitted and none added;
#:   * `*_verifying_key_sha256` = SHA-256 over the RAW 32-BYTE Ed25519 key.
#:
#: ⚠ THE RAW KEY, NOT THE PEM, AND THE CHOICE IS MEASURED RATHER THAN INHERITED.
#: 's succession statement digests the key's PEM TEXT. PEM is a CONTAINER,
#: not a key format: the same key re-wrapped digests
#: differently, and -- decisively -- a entry does not
#: carry a PEM at all. Its `public_key` is base64 DER. So a statement bound to
#: PEM text CANNOT BE CHECKED against the directory it is supposed to be part
#: of; the binding names bytes the format does not hold.
#:
#: Consequence, stated plainly: 's succession SIGNATURE is valid
#: and reproducible, but its key-binding fields are over the wrong encoding, so
#: the succession STATEMENT must be re-emitted under this form. The chain's
#: records and checkpoints are untouched by that.
SUCCESSION_STATEMENT_KEYS = (
    "claim",
    "closing_checkpoint_statement_hash",
    "predecessor_era",
    "predecessor_verifying_key_sha256",
    "signed_at_kernel_time",
    "successor_era",
    "successor_verifying_key_sha256",
)
SUCCESSION_FORMS = {SUCCESSION_FORM_ID: SUCCESSION_STATEMENT_KEYS}


#: `KD-013`: 64 lowercase hexadecimal characters, exactly.
_HEX64 = re.compile(r"[0-9a-f]{64}")


class KeyDirectoryError(Exception):
    pass


def parse_public_key(pem: str, *, allow_legacy: bool = False) -> bytes:
    """Return the raw 32-byte Ed25519 verifying key from `public_key`.

    ⚠ — ACCEPTED, not yet fixed: §2 says `public_key` is
    "PEM-encoded" and says nothing more. PEM is a container, not a key format —
    the body could be an RFC 8410 SubjectPublicKeyInfo, a bare 32-byte key, or
    something else, and a verifier that guesses wrong fails on every signature.
    `ERRATA_P3_02` accepted the finding and deferred the fix. ⚠ THE DEFERRAL IS
    SPENT AND THIS SENTENCE OUTLIVED IT: the fix was made and the
    encoding is declared at `KD-011`
    with `KD-010`. Corrected
    DATE: closed.
    *A deferral that is never retired reads as an open item for as long as it
    sits there, and this one advertised a gap the programme had already shut.*

    Chose SPKI (`-----BEGIN PUBLIC KEY-----`), because it is what "PEM-encoded
    public key" denotes everywhere else and it is self-describing about the
    algorithm. A bare 32-byte body is also accepted, so a directory using the
    other convention is visible rather than silently broken.
    """
    if not isinstance(pem, str):
        raise KeyDirectoryError("public_key must be a string")

    # ── KD-010 (DRAFT): A HASH OF A KEY IS NOT A KEY ─────────
    # 's key directory carried `verifying_key_sha256` where the format
    # wants `public_key`. Its era-2 entry held a 64-character hex digest and
    # NOTHING ELSE -- the key was never recorded and is unrecoverable.
    #
    # As written it already failed, but with "unrecognised public_key encoding
    # (48 bytes)" -- a message about base64 arithmetic that names neither the
    # fault nor the field. A reader would have hunted an encoding bug.
    stripped = pem.strip()
    armoured = stripped.startswith("-----BEGIN PUBLIC KEY-----")
    if len(stripped) == 64 and all(c in "0123456789abcdefABCDEF" for c in stripped):
        raise KeyDirectoryError(
            "KD-010: public_key holds a 64-character HEX DIGEST, not a key. A "
            "hash of a public key is not a public key: it cannot verify a "
            "signature, and an entry carrying one asserts an era exists while "
            "making every record under it unverifiable. If this came from a "
            "`verifying_key_sha256` field, the key itself must be recorded")

    lines = [ln.strip() for ln in pem.strip().splitlines()]
    body = "".join(ln for ln in lines if ln and not ln.startswith("-----"))
    try:
        der = base64.b64decode(body, validate=True)
    except Exception as exc:
        raise KeyDirectoryError("public_key is not valid base64") from exc

    if len(der) == 44 and der.startswith(_SPKI_ED25519_PREFIX):
        # KD-011 (DRAFT): the conforming encoding. Armoured or not, the body is
        # an RFC 8410 SubjectPublicKeyInfo.
        if not armoured and not allow_legacy:
            raise KeyDirectoryError(
                "KD-011-ENCODING: public_key carries a bare base64 "
                "SubjectPublicKeyInfo. KD-011 requires PEM armour "
                "('-----BEGIN PUBLIC KEY-----'). Pass allow_legacy=True only "
                "for a directory published before KD-011, and re-publish it")
        return der[12:]
    if len(der) == 32:
        # ⚠ AND THE HALF NO CHECK CLOSES (BV-031 limb 2's shape, in a new
        # place): A 32-BYTE VALUE THAT IS NOT A KEY IS INDISTINGUISHABLE FROM
        # ONE THAT IS. A SHA-256 digest is exactly 32 bytes, so a digest
        # base64'd into this slot is accepted here and fails later as a
        # signature mismatch --, not reasoned about.
        #
        # ⚠ left this accepted because the specification said only
        # "PEM-encoded" -- a container -- so a bare 32-byte body was neither
        # clearly conforming nor clearly not. KD-011 names the encoding, so the
        # question is now answerable and the answer is no.
        if not allow_legacy:
            raise KeyDirectoryError(
                "KD-011-ENCODING: public_key carries a bare 32-byte value. "
                "KD-011 requires a PEM-armoured RFC 8410 SubjectPublicKeyInfo, "
                "which is self-describing about the algorithm; a bare 32 bytes "
                "is not, and is indistinguishable from a SHA-256 digest. "
                "Pass allow_legacy=True only for a directory "
                "published before KD-011, and re-publish it")
        return der                                    # legacy bare-key convention
    raise KeyDirectoryError(
        f"unrecognised public_key encoding ({len(der)} bytes); expected an "
        "Ed25519 SubjectPublicKeyInfo (44 bytes) or a bare 32-byte key"
    )


class Succession:
    """KD-009 (DRAFT): an era's cryptographic link to the one before it."""

    __slots__ = ("form_id", "predecessor_era", "statement", "signature", "raw")

    def __init__(self, era: str, block: Mapping[str, Any]) -> None:
        if not isinstance(block, Mapping):
            raise KeyDirectoryError(
                f"era {era!r}: KD-009-MALFORMED: succession must be a mapping")
        for key in ("form_id", "predecessor_era", "statement", "signature"):
            if key not in block:
                raise KeyDirectoryError(
                    f"era {era!r}: KD-009-MALFORMED: succession is missing {key!r}")
        self.form_id = block["form_id"]
        if self.form_id not in SUCCESSION_FORMS:
            # BV-004's discipline: the recognised set has NO DEFAULT. A verifier
            # that invents a construction and then applies it has certified its
            # own guess.
            raise KeyDirectoryError(
                f"era {era!r}: KD-009-FORM: unrecognised succession form "
                f"{self.form_id!r}; this verifier will not guess what the "
                "signature covers")
        self.predecessor_era = block["predecessor_era"]
        self.statement = block["statement"]
        if not isinstance(self.statement, Mapping):
            raise KeyDirectoryError(
                f"era {era!r}: KD-009-MALFORMED: succession statement must be a mapping")
        expected = SUCCESSION_FORMS[self.form_id]
        got = tuple(sorted(self.statement))
        if got != tuple(sorted(expected)):
            # CEF-001's closed-field-set discipline. The covered material is
            # fixed by the form; a statement of another shape is not this form.
            raise KeyDirectoryError(
                f"era {era!r}: KD-009-FORM: statement carries {got!r}; "
                f"{self.form_id!r} covers exactly {tuple(sorted(expected))!r}")
        try:
            self.signature = base64.b64decode(block["signature"], validate=True)
        except Exception as exc:
            raise KeyDirectoryError(
                f"era {era!r}: KD-009-MALFORMED: signature is not valid base64") from exc
        if len(self.signature) != 64:
            raise KeyDirectoryError(
                f"era {era!r}: KD-009-MALFORMED: an ed25519 signature is 64 bytes; "
                f"got {len(self.signature)}")
        self.raw = block

    def covered_bytes(self) -> bytes:
        """The bytes the signature covers. RECOMPUTED, never taken on trust."""
        from .canonical_form import canonical_bytes
        return canonical_bytes(dict(self.statement))


class EraKey:
    __slots__ = ("era", "algorithm", "public_key", "public_key_pem",
                 "valid_from", "valid_until", "status", "succession")

    def __init__(self, entry: Mapping[str, Any]) -> None:
        self._require_shape(entry)
        self.era = entry["era"]
        self.algorithm = entry["algorithm"]
        self.public_key = parse_public_key(
            entry["public_key"], allow_legacy=bool(entry.get("legacy_encoding")))
        self.valid_from = entry["valid_from"]
        self.public_key_pem = entry["public_key"]
        self.valid_until = entry.get("valid_until")   # absent while current
        self.status = entry["status"]

        # ── KD-012 (DRAFT), ───────────────────────────────────
        # :27 reads, verbatim:
        #     | `valid_from` | the first instant records were signed under this era |
        # "Instant" names no encoding.: this field accepted an
        # int, 0, an ISO-8601 string, a float and None -- and KD-002's overlap
        # check then died of a bare TypeError comparing str with int.
        #
        # KD-012 names it: INTEGER MICROSECONDS SINCE THE UNIX EPOCH, the same
        # construction:37 already names for
        # `kernel_time` ("integer ... microseconds since epoch"). Refused here,
        # BY NAME, so the comparison KD-002 makes is always well-defined.
        for field, value in (("valid_from", self.valid_from),
                             ("valid_until", self.valid_until)):
            if field == "valid_until" and value is None:
                continue                       # absent while the era is current
            if isinstance(value, bool) or not isinstance(value, int):
                raise KeyDirectoryError(
                    f"era {self.era!r}: KD-012-ENCODING: {field} is "
                    f"{type(value).__name__}; KD-012 requires an INTEGER of "
                    "microseconds since the Unix epoch. A directory whose "
                    "instants are not comparable makes KD-002's overlap check "
                    "undefined, and an undefined check is not a check")
        succ = entry.get("succession")
        self.succession = Succession(self.era, succ) if succ is not None else None

        # ── KD-011 limb 4, AS AMENDED ───────────────────────────────
        # ⚠ The flag as I drafted it re-opened the hole limb 2 exists to close:
        # it accepted "a bare 32-byte body", and a base64'd SHA-256 digest IS a
        # bare 32-byte body -- so 's own artefact would have passed through
        # the migration path.
        #
        # THE FLAG DOES NOT GRANT TRUST, IT REQUESTS A DIFFERENT PROOF. A
        # legacy entry MUST be EXERCISED: its key must verify at least one
        # signature attributable to this era. A digest cannot verify anything,
        # so USE is the one test that separates a key from a value shaped like
        # one -- the distinction limb 2 correctly says FORM cannot make.
        # ⚠: THESE TWO REFUSALS USED TO LIVE AT THE END OF
        # `_require_exercise`, WHICH RUNS ONLY WHEN `legacy_encoding` IS SET — so a
        # NORMAL directory entry was never algorithm-checked and never
        # status-checked. `KeyDirectory` accepted `algorithm: "totally-made-up"`
        # and `status: "banana"` without complaint.
        #
        # `selftest_t2.py` had been reporting exactly this for fifteen packs and
        # nothing read it. **The selftest was right and the code was
        # wrong**, which is why 's instruction to "re-cut the stale
        # selftests" was declined for this one: re-cutting it would have deleted
        # the only standing report of a live defect.
        #
        # 's finding, one file along: *a guard that exists and is not
        # invoked is indistinguishable from a guard that was never written,
        # except that it reads as protection.*
        if self.algorithm != "ed25519":
            # CP-003's discipline applied to algorithms: never assume, never
            # fall back to the one you happen to implement. And per ERR-P3-006,
            # "ed25519" here means RFC 8032 §5.1.7 cofactorless specifically.
            raise KeyDirectoryError(
                f"era {self.era!r}: unsupported algorithm {self.algorithm!r}; "
                "this verifier implements ed25519 only and will not guess"
            )
        if self.status not in (CURRENT, RETIRED, COMPROMISED):
            raise KeyDirectoryError(f"era {self.era!r}: unknown status {self.status!r}")

        if entry.get("legacy_encoding"):
            self._require_exercise(entry)

    @staticmethod
    def _require_shape(entry: Any) -> None:
        """Refuse a malformed entry BY NAME, before any field is read.

        ⚠ The era cannot be named in these messages the way every other refusal
        in this file names it, because the era identifier is itself one of the
        fields that may be missing. The entry is described instead, and the
        KEY it was filed under is added by the caller, which does have it.
        """
        if not isinstance(entry, Mapping):
            raise KeyDirectoryError(
                f"{SHAPE_RULE}-ENTRY-NOT-A-MAPPING: a directory entry must be a "
                f"mapping of the fields the key-directory format names; this one "
                f"is a {type(entry).__name__}")
        missing = [f for f in REQUIRED_ERA_FIELDS if f not in entry]
        if missing:
            raise KeyDirectoryError(
                f"{SHAPE_RULE}-MISSING-FIELD: the entry is missing "
                f"{', '.join(repr(f) for f in missing)}. The key-directory format "
                f"requires {', '.join(repr(f) for f in REQUIRED_ERA_FIELDS)}; "
                f"`valid_until` is absent while an era is current and is not "
                f"required. A verifier MUST NOT guess a key, and it must not "
                f"guess the entry that names one either")

    def _require_exercise(self, entry: Mapping[str, Any]) -> None:
        import base64 as _b64

        from .ed25519 import verify as ed25519_verify
        ex = entry.get("legacy_exercise")
        if not isinstance(ex, Mapping) or "message" not in ex or "signature" not in ex:
            raise KeyDirectoryError(
                f"era {self.era!r}: KD-011-UNEXERCISED: legacy_encoding is set and "
                "no legacy_exercise was supplied. A legacy entry must be EXERCISED "
                "-- its key must verify a signature attributable to this era. The "
                "flag requests a different proof; it does not grant trust")
        try:
            message = _b64.b64decode(ex["message"], validate=True)
            signature = _b64.b64decode(ex["signature"], validate=True)
        except Exception as exc:
            raise KeyDirectoryError(
                f"era {self.era!r}: KD-011-UNEXERCISED: legacy_exercise message or "
                "signature is not valid base64") from exc
        if len(signature) != 64 or not ed25519_verify(self.public_key, message, signature):
            raise KeyDirectoryError(
                f"era {self.era!r}: KD-011-UNEXERCISED: the legacy_exercise signature "
                "does not verify under this entry's public_key. ⚠ A SHA-256 DIGEST "
                "CANNOT VERIFY A SIGNATURE -- this is the test that separates a key "
                "from a 32-byte value shaped like one, which KD-011 limb 2 says form "
                "cannot do")

    # KD-007: `retired` means "no longer signing", NEVER "no longer trusted".
    # Rotation never invalidates earlier records, so a retired era still verifies.
    @property
    def verifies(self) -> bool:
        return self.status in (CURRENT, RETIRED)

    @property
    def compromised(self) -> bool:
        """KD (§4): records under a compromised key can no longer be relied on as
        evidence of origin — someone else may have been able to produce them.
        The directory records the fact; it cannot repair it."""
        return self.status == COMPROMISED


class KeyDirectory:
    """A mapping from era identifier to entry (§2).

     RULED by `ERRATA_P3_02`: on a two-copy disagreement the
    verifier **MUST REFUSE**, per the refusal-over-guessing discipline — *"a
    verifier that picks a copy has chosen which authority to trust."*
    `cross_check` reports; `assert_agrees` refuses. The T-2 behaviour (report,
    decline to pick, but keep going) is superseded.
    """

    def __init__(self, entries: Mapping[str, Mapping[str, Any]]) -> None:
        if not isinstance(entries, Mapping):
            raise KeyDirectoryError(
                f"{SHAPE_RULE}-NOT-A-MAPPING: the key directory must be a mapping "
                f"from era identifier to entry; this "
                f"one is a {type(entries).__name__}")
        self.eras = {}
        for era, entry in entries.items():
            try:
                self.eras[era] = EraKey(entry)
            except KeyDirectoryError as exc:
                # ⚠ The entry could not name its own era, so the key it was
                # filed under is added here. Re-raised, never swallowed.
                raise KeyDirectoryError(f"era {era!r}: {exc}") from None
        self._check_no_overlap()
        self._check_successions()

    # ── KD-009 (DRAFT) ──────────────────────────────────────────────────────
    def _check_successions(self) -> None:
        """Verify every era's link to its predecessor.

        ⚠ Runs at the DIRECTORY level and not on EraKey, because verifying a
        succession needs the PREDECESSOR'S KEY, which one entry does not have.
        That is why found this missing: the evidence was not merely
        unchecked, it had nowhere to live.
        """
        import hashlib

        from .ed25519 import verify as ed25519_verify

        for era in sorted(self.eras):
            key = self.eras[era]
            succ = key.succession
            if succ is None:
                continue          # KD-009-ABSENT is raised by require_succession
            prev = self.eras.get(succ.predecessor_era)
            if prev is None:
                raise KeyDirectoryError(
                    f"era {era!r}: KD-009-PREDECESSOR: succession names "
                    f"{succ.predecessor_era!r}, which is not in this directory. "
                    "A link to a key the reader does not hold is not a link")

            st = succ.statement
            # ── binding, BEFORE any cryptography ────────────────────────────
            # A signature that verifies over a statement about a DIFFERENT
            # succession is a valid signature and worthless evidence here.
            for field, expected, what in (
                    ("successor_era", era, "this era"),
                    ("predecessor_era", succ.predecessor_era, "the named predecessor")):
                if st.get(field) != expected:
                    raise KeyDirectoryError(
                        f"era {era!r}: KD-009-BINDING: statement {field}="
                        f"{st.get(field)!r} does not name {what} ({expected!r}). "
                        "The covered material is about another succession")
            for field, holder in (("successor_verifying_key_sha256", key),
                                  ("predecessor_verifying_key_sha256", prev)):
                digest = hashlib.sha256(holder.public_key).hexdigest()
                if st.get(field) != digest:
                    raise KeyDirectoryError(
                        f"era {era!r}: KD-009-BINDING: statement {field} does not "
                        f"match era {holder.era!r}'s key under {succ.form_id!r} "
                        "(SHA-256 over the RAW 32-byte key)")

            # ── the signature, over bytes RECOMPUTED from the statement ─────
            if ed25519_verify(prev.public_key, succ.covered_bytes(), succ.signature):
                continue

            # ⚠ It failed. CP-008: a failing signature does not say WHY, and
            # this refusal must not pretend otherwise. But where the evidence
            # DOES separate causes, separate them: if some other era in this
            # directory signed these bytes, that is a stronger, nameable fault.
            for other in sorted(self.eras):
                if other == succ.predecessor_era:
                    continue
                if ed25519_verify(self.eras[other].public_key,
                                  succ.covered_bytes(), succ.signature):
                    raise KeyDirectoryError(
                        f"era {era!r}: KD-009-WRONG-KEY: the succession is signed "
                        f"by era {other!r}, not by the named predecessor "
                        f"{succ.predecessor_era!r}. Authority does not chain from "
                        "a key that was not the outgoing one")
            raise KeyDirectoryError(
                f"era {era!r}: KD-009-SIGNATURE: the succession signature does not "
                f"verify under era {succ.predecessor_era!r}'s key over the bytes "
                f"{succ.form_id!r} names. This is absence of attestation, not proof "
                "of forgery, and it does not distinguish altered bytes from an "
                "unknown signer (CP-008)")

    def verify_boundary_witnessed(self, era: str, *, closing_statement_bytes: bytes,
                                  witness_key_ref: str, witness_signature: bytes,
                                  trust_list) -> None:
        """KD-006 (DRAFT limb): the era boundary is marked by a WITNESSED checkpoint.

        `KD-009`'s statement already binds the closing checkpoint by hash; this
        verifies that a witness attested THAT checkpoint, and that the witness
        is one this verifier was provisioned to trust.

        ⚠⚠ AND THE LIMIT IS PART OF THE CONTRACT, NOT A FOOTNOTE ON IT
        (BV-031 limb 2's discipline, applied to a different kind of limit):

        > A WITNESS WHOSE KEY THE OPERATOR HOLDS ATTESTS TO NOTHING THE
        > OPERATOR COULD NOT HAVE FORGED.

        Passing this check establishes INTERNAL CONSISTENCY -- that the
        boundary the succession names is the one that was attested -- and NOT
        INDEPENDENCE. It is worth exactly what the trust list is worth, and
        `ERR-CP-001` already rules that an anchored witness run by the operator
        passes. 's own witness was synthetic and operator-held, so this
        check would have passed over it and established nothing.

        What it DOES establish, and it is not nothing: that the succession and
        the witnessed checkpoint refer to the same boundary. A rotation whose
        statement names one checkpoint while the attestation covers another is
        caught here and is caught nowhere else.
        """
        import hashlib

        from .ed25519 import verify as ed25519_verify

        key = self.eras[era]
        if key.succession is None:
            raise KeyDirectoryError(
                f"era {era!r}: KD-006: no succession, so no boundary to witness")
        named = key.succession.statement["closing_checkpoint_statement_hash"]
        actual = hashlib.sha256(closing_statement_bytes).hexdigest()
        if actual != named:
            raise KeyDirectoryError(
                f"era {era!r}: KD-006-BOUNDARY: the succession names closing "
                f"checkpoint {named[:12]}... and the statement supplied hashes to "
                f"{actual[:12]}.... The attestation covers a different boundary")
        anchor = trust_list.anchor_for(witness_key_ref)
        if anchor is None:
            # There is no default and no discovery (witness.py). A verifier that
            # trusts a witness because a bundle named it has anchored nothing.
            raise KeyDirectoryError(
                f"era {era!r}: KD-006-UNTRUSTED: witness {witness_key_ref!r} is not "
                "in the provisioned trust list. This is a fact about the VERIFIER, "
                "not about the boundary")
        if not ed25519_verify(anchor.key_material, closing_statement_bytes,
                              witness_signature):
            raise KeyDirectoryError(
                f"era {era!r}: KD-006-SIGNATURE: the witness attestation does not "
                f"verify under trusted witness {witness_key_ref!r}. Absence of "
                "attestation, not proof of forgery (CP-008)")

    def require_succession(self, era: str) -> None:
        """KD-009 limb 1: a non-genesis era MUST carry one."""
        key = self.eras[era]
        if key.succession is None:
            raise KeyDirectoryError(
                f"era {era!r}: KD-009-ABSENT: no succession block. D6 requires a "
                "new era key to be signed by the outgoing era key; this directory "
                "asserts the era exists and offers no evidence that it succeeded "
                "anything. Two keys with validity windows are not a chain")

    def _check_no_overlap(self) -> None:
        # KD-002: eras do not overlap; every sealed record falls in exactly one.
        windows = sorted(
            ((k.valid_from, k.valid_until, k.era) for k in self.eras.values()),
            key=lambda w: w[0],
        )
        for (f1, u1, e1), (f2, _, e2) in zip(windows, windows[1:]):
            if u1 is None:
                raise KeyDirectoryError(
                    f"era {e1!r} has no valid_until but era {e2!r} starts later "
                    "(KD-002: eras do not overlap)"
                )
            if u1 > f2:
                raise KeyDirectoryError(f"eras {e1!r} and {e2!r} overlap (KD-002)")

    def covers_at(self, era: str, when: int) -> bool:
        """Whether `era`'s window contains `when`. ⚠ Resolution first, so an
        unknown era REFUSES rather than answering `False` — *"no" and "I have
        never heard of it" are different answers and `KD-003` already refuses
        to guess.*"""
        key = self.resolve(era)
        if not isinstance(when, int) or isinstance(when, bool):
            raise KeyDirectoryError(
                f"KD-013-ENCODING: an instant offered for era {era!r} is "
                f"{type(when).__name__}; `KD-012` fixes these as INTEGER "
                "microseconds since the Unix epoch on both sides of the "
                "comparison, or the comparison is undefined")
        if when < key.valid_from:
            return False
        return key.valid_until is None or when < key.valid_until

    def resolve_at(self, era: str, when: int) -> EraKey:
        """`resolve`, and then REFUSE unless the era's window contains `when`.

        ⚠⚠ **`KD-013` — THE WINDOW WAS DECLARED AND NEVER APPLIED.** This
        directory has carried `valid_from` and `valid_until` from the start and
        checked them only against EACH OTHER: `KD-002` for overlap, `KD-001`
        for immutability. Nothing compared them to a record. `resolve` takes an
        era name and returns a key, so a retired era's key verified an instant
        from any point in history and the directory raised no objection.

        > ***A KEY THAT VERIFIES A RECORD FROM ANY INSTANT IS NOT SCOPED TO AN
        > ERA; IT IS SCOPED TO ITS OWN EXISTENCE.***

        ⚠ **THE INTERVAL IS HALF-OPEN, `[valid_from, valid_until)`, AND THAT IS
        THIS FILE'S OWN ARITHMETIC RATHER THAN A CHOICE MADE HERE.**
        `_check_no_overlap` refuses on `u1 > f2` and admits `u1 == f2`, so one
        era may end exactly where the next begins. Only a half-open reading
        makes `KD-002`'s own sentence true — *every sealed record falls in
        exactly one* — because under a closed interval a boundary instant falls
        in two.

        ⚠ `valid_until is None` is unbounded above: absence, not a sentinel.
        """
        key = self.resolve(era)
        if self.covers_at(era, when):
            return key
        raise KeyDirectoryError(
            f"era {era!r}: KD-013-OUTSIDE-WINDOW: the instant {when} is not in "
            f"[{key.valid_from}, "
            f"{'∞' if key.valid_until is None else key.valid_until}). The key "
            f"resolves and is not entitled to this instant — which is a "
            f"different finding from a bad signature and is reported as one")

    def resolve(self, era: str) -> EraKey:
        try:
            key = self.eras[era]
        except KeyError:
            raise KeyDirectoryError(
                f"era {era!r} is not in the directory; a verifier MUST NOT guess a key"
            ) from None
        if not key.verifies:
            raise KeyDirectoryError(f"era {era!r} is marked {key.status}")
        return key

    def assert_agrees(self, other: "KeyDirectory") -> None:
        """A-26 as ruled. Raises on any disagreement between the published copy
        and the in-chain copy — never picks a winner, never continues."""
        findings = self.cross_check(other)
        if findings:
            raise KeyDirectoryError(
                "KD-003: the published and in-chain key directories disagree; "
                "refusing to verify under either — " + "; ".join(findings))

    # ── KD-013 (RATIFIED ) ───────────────────────────────────────────
    @staticmethod
    def directory_digest(published_bytes: bytes) -> str:
        """`KD-013`'s NAMED construction, and nothing else.

        **SHA-256 of the artefact's EXACT PUBLISHED BYTES — no canonicalisation
        step — as 64 lowercase hexadecimal characters.**

        ⚠ The absence of a canonicalisation step is the point, not an omission.
        A canonicalising construction would make directory-lineage verification
        depend on canonicalisation agreement, importing `CF-*` risk into `KD-*`
        for no gain. A verifier hashes what it RECEIVED.
        """
        return hashlib.sha256(published_bytes).hexdigest()

    @staticmethod
    def check_prior_digest(published_bytes: bytes,
                           predecessor_bytes: bytes | None,
                           *,
                           legacy_digests: frozenset[str]) -> None:
        """`KD-013`: verify a directory's link to its predecessor. Raises or returns.

        `published_bytes` is the directory AS PUBLISHED — the same bytes a reader
        received, not a re-serialisation of a parsed copy. Passing re-serialised
        bytes is the one way to make this check pass on an artefact that would
        fail for a real reader, which is why the parameter is bytes and not a dict.

        `legacy_digests` is the CLOSED, ENUMERATED legacy set. `KD-013`: *"a legacy
        version is recognised by its registered digest and by nothing else."* It is
        DERIVED from `REGISTERS/KEY_DIRECTORY_LEGACY_SET.md` and never restated
        (`SEAT-001`); this function takes it as a provisioned input with no default,
        because a default would let an unregistered directory pass as legacy.
        """
        directory = json.loads(published_bytes.decode("utf-8"))

        own = KeyDirectory.directory_digest(published_bytes)
        if own in legacy_digests:
            return                      # a registered legacy version, and nothing else

        if "prior_directory_digest" not in directory:
            raise KeyDirectoryError(
                "KD-013: prior_directory_digest is ABSENT. The field is never "
                "absent for a version published after ratification; absence is a "
                "refusal and is never inferred around (KD-009's discipline). This "
                "directory's digest is not in the registered legacy set either")

        claimed = directory["prior_directory_digest"]

        if claimed is None:
            if predecessor_bytes is not None:
                raise KeyDirectoryError(
                    "KD-013: prior_directory_digest is null (genesis) but a "
                    "predecessor was supplied; genesis has no predecessor")
            return

        if not (isinstance(claimed, str) and _HEX64.fullmatch(claimed)):
            raise KeyDirectoryError(
                "KD-013: prior_directory_digest must be 64 lowercase hexadecimal "
                f"characters; got {claimed!r}")

        if own == claimed:
            raise KeyDirectoryError(
                "KD-013: a directory MUST NOT carry its own digest — the "
                "predecessor is a different set, and a set containing its own "
                "digest has no fixpoint (PIN-002)")

        if predecessor_bytes is None:
            raise KeyDirectoryError(
                "KD-013: prior_directory_digest names a predecessor but none was "
                "supplied; the link cannot be checked and is not assumed")

        actual = KeyDirectory.directory_digest(predecessor_bytes)
        if actual != claimed:
            raise KeyDirectoryError(
                "KD-013: the predecessor's digest does not match the value this "
                f"directory carries — claimed {claimed}, computed {actual}. The "
                "published history has been rewritten between these versions")

    def cross_check(self, other: "KeyDirectory") -> list[str]:
        """KD-003. Returns the list of disagreements between the published copy
        and the in-chain copy. An empty list is the only clean result."""
        findings = []
        for era in sorted(set(self.eras) | set(other.eras)):
            a, b = self.eras.get(era), other.eras.get(era)
            if a is None or b is None:
                findings.append(f"era {era!r} present in only one copy")
                continue
            # KD-001: public_key, algorithm and valid_from are immutable once
            # published. A difference in those is the serious kind.
            for field in ("public_key", "algorithm", "valid_from"):
                if getattr(a, field) != getattr(b, field):
                    findings.append(f"era {era!r}: immutable field {field!r} differs (KD-001)")
            for field in ("valid_until", "status"):
                if getattr(a, field) != getattr(b, field):
                    findings.append(f"era {era!r}: {field!r} differs")
        return findings
