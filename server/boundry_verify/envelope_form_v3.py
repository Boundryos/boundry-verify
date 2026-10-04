"""The Canonical Envelope Form, version 3 — the leaf with a sealed author.

⚠ **WRITTEN INDEPENDENTLY OF THE SUBSTRATE AND IMPORTING NOTHING FROM IT.**
The two-roads discipline: the fifteen agreement-by-design pairs are
worth what they are because neither side reads the other. This module was
written from the specification and the v2 form's stated rules, and
`agreement_sweep` is what holds it to the other road.

⚠ **GENESIS IS EXPRESSED BY OMISSION HERE, NOT BY A SENTINEL.** v1 carries
`prev_envelope_hash` always, with `""` for genesis, and `ERR-P3-001` ruled that
a verifier holding one v1 envelope cannot infer genesis from it — the value
would be testing itself. **v2 changed the representation and v3 inherits it**:
the key is ABSENT at genesis, so absence is unambiguous and `is_genesis` is not
an input. *The rule did not weaken; the form stopped needing it.*

⚠ **WHAT v3 ADDS, AND WHY IT IS INSIDE THE BYTES.** Phase 7 made the
submitter recorded against a record the principal the kernel AUTHENTICATED. It
left that value a column beside the seal, so anyone who could write the database
could change it without breaking a signature or an identity. In v3 the author is
in the mapping the leaf hash is taken over: changing it breaks the leaf, the
inclusion proof and the checkpoint at once.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .canonical_form import canonical_bytes
# ⚠ **IMPORTED, NEVER RETYPED**. v3 forbids exactly the digests v1
# forbids, for exactly v1's reason. A first draft re-declared them and the
# governance sweep caught it as an undeclared equal-digest pair — correctly:
# two copies of one rule are one rule and two places for it to stop working
# (`K-6b`). ⚠ This is an import WITHIN one road, which the two-roads rule does
# not touch: what it forbids is `boundry_verify` reading the SUBSTRATE.
from .envelope_form import FORBIDDEN_PREV_HASHES

__all__ = [
    "CanonicalEnvelopeFormV3Error",
    "DISPATCH_KEY", "CEF_V3_VERSION", "CEF_V3_KEYS", "CEF_V3_OPTIONAL_KEYS",
    "envelope_canonical_form_v3", "envelope_canonical_bytes_v3",
    "envelope_leaf_hash_v3",
]

#: ⚠ **THE KEY THAT NAMES A VERSION, AND ITS HOME ON THIS ROAD.**
#: It was a literal in `envelope_dispatch` AND a second,
#: independent literal in `CEF_V3_KEYS` below, **so a move of one would not
#: have moved the other.**
#:
#: It lives HERE and not in `envelope_dispatch` because `envelope_dispatch`
#: imports this module and the reverse would be a cycle; and not in
#: `envelope_form` because that module is derived from
#: the envelope-form specification **alone** and v1 is identified by this
#: key's ABSENCE. **v3 is the first form on this road that carries it, which is
#: the same answer the substrate road gives** — there `DISPATCH_KEY` lives in
#: `canonical_envelope_v2`, the module of the first form to carry the key.
DISPATCH_KEY = "canonical_version"

CEF_V3_VERSION = 3

#: The v3 key set. `prev_envelope_hash` is absent at genesis;
#: `submitter_domain_ref` is absent when the principal has no domain.
CEF_V3_KEYS = (
    DISPATCH_KEY,
    "envelope_kind",
    "payload_hash",
    "position",
    "prev_envelope_hash",
    "submitter_domain_ref",
    "submitter_principal_id",
    "transition_timestamp_us",
)

#: ⚠ `submitter_principal_id` IS NOT HERE. A v3 envelope with no author is a
#: contradiction: carrying one is what the version is for.
CEF_V3_OPTIONAL_KEYS = frozenset({"prev_envelope_hash", "submitter_domain_ref"})

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class CanonicalEnvelopeFormV3Error(ValueError):
    """A v3 structural refusal, with the clause it rests on."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def envelope_canonical_form_v3(
    *,
    envelope_kind: str,
    payload_hash: str,
    position: int,
    prev_envelope_hash: str | None,
    transition_timestamp_us: int,
    submitter_principal_id: str,
    submitter_domain_ref: str | None = None,
) -> dict[str, Any]:
    """Build and validate the v3 mapping."""
    if not isinstance(envelope_kind, str) or not envelope_kind:
        raise CanonicalEnvelopeFormV3Error(
            "CEF-001", "envelope_kind must be a non-empty string")
    if not isinstance(payload_hash, str) or not _HEX64.match(payload_hash):
        raise CanonicalEnvelopeFormV3Error(
            "CEF-001", "payload_hash must be 64 lowercase hex digits")
    if isinstance(position, bool) or not isinstance(position, int):
        raise CanonicalEnvelopeFormV3Error("CEF-001", "position must be an integer")
    if position < 0:
        raise CanonicalEnvelopeFormV3Error(
            "CEF-001", "position is zero-based and must not be negative")
    if isinstance(transition_timestamp_us, bool) or not isinstance(
            transition_timestamp_us, int):
        raise CanonicalEnvelopeFormV3Error(
            "CEF-001", "transition_timestamp_us must be an integer of microseconds")
    if transition_timestamp_us < 0:
        raise CanonicalEnvelopeFormV3Error(
            "CEF-001", "transition_timestamp_us must not be negative")

    # ⚠ CEF-007 over PRESENCE. Genesis is position 0 and is expressed by the
    # key's absence; the biconditional is enforced in both directions.
    is_genesis = position == 0
    is_absent = prev_envelope_hash is None
    if is_genesis != is_absent:
        if is_genesis:
            raise CanonicalEnvelopeFormV3Error(
                "CEF-007",
                "a genesis envelope (position 0) must OMIT prev_envelope_hash; "
                "it claims a predecessor that does not exist")
        raise CanonicalEnvelopeFormV3Error(
            "CEF-007",
            f"a non-genesis envelope (position {position}) must carry a "
            "predecessor hash; omitting it would detach it from the chain "
            "while still hashing to a leaf that looks perfectly valid")

    if not isinstance(submitter_principal_id, str) or not submitter_principal_id:
        raise CanonicalEnvelopeFormV3Error(
            "CEF-V3-001",
            "submitter_principal_id must be a non-empty string: a v3 envelope "
            "with no author is a contradiction")
    if submitter_domain_ref is not None and (
            not isinstance(submitter_domain_ref, str) or not submitter_domain_ref):
        raise CanonicalEnvelopeFormV3Error(
            "CEF-V3-001",
            "submitter_domain_ref must be a non-empty string when present; "
            "absence is expressed by omitting the key")

    form: dict[str, Any] = {
        DISPATCH_KEY: CEF_V3_VERSION,
        "envelope_kind": envelope_kind,
        "payload_hash": payload_hash,
        "position": position,
        "submitter_principal_id": submitter_principal_id,
        "transition_timestamp_us": transition_timestamp_us,
    }
    if not is_absent:
        if prev_envelope_hash in FORBIDDEN_PREV_HASHES:
            raise CanonicalEnvelopeFormV3Error(
                "CEF-008",
                f"prohibited digest {prev_envelope_hash[:12]}…: it is "
                "syntactically valid, which is why it is excluded by name")
        if not _HEX64.match(prev_envelope_hash):
            raise CanonicalEnvelopeFormV3Error(
                "CEF-004", "prev_envelope_hash must be 64 lowercase hex digits")
        form["prev_envelope_hash"] = prev_envelope_hash
    if submitter_domain_ref is not None:
        form["submitter_domain_ref"] = submitter_domain_ref
    return form


def envelope_canonical_bytes_v3(**kwargs: Any) -> bytes:
    """The canonical bytes of one v3 envelope. No new emission rules."""
    return canonical_bytes(envelope_canonical_form_v3(**kwargs))


def envelope_leaf_hash_v3(**kwargs: Any) -> str:
    """The leaf hash — and, from v2 onward, the record's IDENTITY."""
    return hashlib.sha256(envelope_canonical_bytes_v3(**kwargs)).hexdigest()
