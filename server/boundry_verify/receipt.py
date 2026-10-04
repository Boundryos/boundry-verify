"""Witness receipts — `ERRATA_P3_02` (`ERR-P3-004`, `ERR-P3-005`, `ERR-P3-007`).

**Status of the governing document.** `ERRATA_P3_02` is **RATIFIED** (30 Aug
2026) and registered in the programme's corpus at sequence
5. Neither the document nor that register ships with this package. What ships
is this module, and the ratified text was re-read and checked clause by clause
against it — they agree. The question is CLOSED.

⚠ One gap remains, and it is not this module's to close: the programme's
working copy of that document still carries **"READY FOR RATIFICATION"** in its
own status line and closing line, and the register entry is the hash of that
text. A document whose status line contradicts its status is the superseded-copy
hazard inside one file. Flagged. Nothing in this
paragraph is a claim about a file in this package.

⚠ **SYNTHETIC.** No witness has ever been contacted and no receipt has ever
been issued.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any, Mapping

from .canonical_form import canonical_bytes
from .checkpoint import CheckpointStatement, witness_message

__all__ = ["ReceiptError", "RECEIPT_KEYS", "RECEIPT_VERSION", "Receipt",
           "KNOWN_WITNESS_KINDS"]

RECEIPT_VERSION = 1

# ERR-P3-005: exactly these five entries. Field set fixed and closed; a change
# is a new `receipt_version`, never an in-place amendment — the same discipline
# as CEF-001 and CP-011.
RECEIPT_KEYS = (
    "attested_digest",
    "receipt_version",
    "witness_key_ref",
    "witness_kind",
    "witness_token",
)

#: ERR-P3-005 names two and allows "a registered identifier". No registry is
#: specified, so an unknown kind is CARRIED, not refused — refusing would make
#: this verifier the registry.
KNOWN_WITNESS_KINDS = ("rfc3161", "rekor")


class ReceiptError(Exception):
    pass


def _is_sha256_hex(s: Any) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


class Receipt:
    """The five-key form, canonicalised."""

    __slots__ = ("raw", "receipt_version", "witness_kind", "attested_digest",
                 "witness_token", "witness_key_ref")

    def __init__(self, receipt: Mapping[str, Any]) -> None:
        missing = [k for k in RECEIPT_KEYS if k not in receipt]
        extra = [k for k in receipt if k not in RECEIPT_KEYS]
        if missing or extra:
            raise ReceiptError(
                f"the receipt's field set is closed; missing={missing} unexpected={extra}")
        self.raw = dict(receipt)
        self.receipt_version = receipt["receipt_version"]
        self.witness_kind = receipt["witness_kind"]
        self.attested_digest = receipt["attested_digest"]
        self.witness_token = receipt["witness_token"]
        self.witness_key_ref = receipt["witness_key_ref"]

        if isinstance(self.receipt_version, bool) or not isinstance(self.receipt_version, int):
            raise ReceiptError("receipt_version must be an integer")
        if self.receipt_version != RECEIPT_VERSION:
            raise ReceiptError(
                f"unknown receipt_version {self.receipt_version!r}; this verifier "
                "will not guess a field set")
        for name in ("witness_kind", "witness_token", "witness_key_ref"):
            if not isinstance(getattr(self, name), str):
                raise ReceiptError(f"{name} must be a string")
        if not _is_sha256_hex(self.attested_digest):
            raise ReceiptError("attested_digest must be 64 lowercase hex digits")
        # The token is opaque but its CONTAINER is checkable: base64 that does
        # not decode is malformed regardless of what it wraps.
        try:
            base64.b64decode(self.witness_token, validate=True)
        except Exception as exc:
            raise ReceiptError("witness_token is not valid base64") from exc

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.raw)

    def attests_to(self, statement: CheckpointStatement) -> bool:
        """ERR-P3-004. Recompute the checkpoint's canonical bytes, hash them, and
        check the receipt attests to THAT digest.

        *"A receipt attesting to any other value does not attest to this
        checkpoint, however valid it is in itself."*

        ERR-P3-007: the attested value is the **raw 32 bytes** of the SHA-256.
        Hex appears only here, inside the canonical-form document.
        """
        return self.attested_digest == witness_message(statement).hex()

    # --- what this verifier CANNOT establish about a receipt -------------
    @property
    def token_verified(self) -> bool:
        """Always False, and that is a property of the design, not a gap in the
        effort. See `unverifiable_because`."""
        return False

    @property
    def unverifiable_because(self) -> tuple[str, ...]:
        return (
            f"the {self.witness_kind!r} token is carried VERBATIM and is opaque to "
            "this verifier by design — checking it would require "
            "implementing that witness's own format, which is outside this pack",
            "the witness's key is named by `witness_key_ref` and must be obtained "
            "FROM THE WITNESS; this verifier makes no network calls, so it has not "
            "been fetched and the token's signature has NOT been checked",
            "`witness_key_ref` is a pointer, not an endorsement",
        )
