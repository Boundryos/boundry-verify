"""The Canonical Envelope Form, version 1 — the Merkle leaf.

Written from the envelope-form specification (RATIFIED v1.0) and
`ERRATA_CEF_v1_flag_meaning_and_construction_v0.1` alone.

⚠ The specification's own status line: PROPOSED — NOT IMPLEMENTED. No record
has ever been sealed under this form, and per ERR-CEF-001 the corpus flag
`implemented_by_kernel: false` asserts that no envelope in this form is
emitted into the chain. Nothing here may be reported as verifying production
data.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .canonical_form import canonical_bytes

__all__ = [
    "CanonicalEnvelopeFormError",
    "CEF_VERSION", "CEF_KEYS", "GENESIS_SENTINEL", "FORBIDDEN_PREV_HASHES",
    "envelope_canonical_form", "envelope_canonical_bytes", "envelope_leaf_hash",
    "verify_chain_links", "BOUND_FIELDS", "UNBOUND_FIELDS",
]

CEF_VERSION = 1                                   # CEF-003

# CEF-001: the field set is FIXED AND CLOSED. Exactly these five keys, always,
# in every envelope. No field is optional and none is ever omitted.
CEF_KEYS = (
    "canonical_envelope_form_version",
    "envelope_kind",
    "payload_hash",
    "position",
    "prev_envelope_hash",
)

GENESIS_SENTINEL = ""                             # CEF-006

# ⚠ CEF-008 (prohibition). The SHA-256 of empty input presents itself as "the
# natural empty hash" and is the single worst available choice: it is exactly
# what a catastrophically broken implementation produces. The all-zeros digest
# is excluded by the same reasoning — it is syntactically valid and therefore
# looks like a value.
SHA256_OF_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ALL_ZEROS = "0" * 64
FORBIDDEN_PREV_HASHES = frozenset({SHA256_OF_EMPTY, ALL_ZEROS})

BOUND_FIELDS = ("payload (by hash)", "envelope kind", "position",
                "entire predecessor history, transitively")
# ⚠ **THE PLAN SEAL JOINS THE UNBOUND**.
# `AuditEnvelope` gained `seal_signature` and `seal_era`, deliberately outside
# identity — which is exactly the claim this tuple exists to make. Neither
# would have failed on its own: this is prose about a set nothing recomputes
# from the class.
#
# > ***A SET THAT SAYS WHAT IS OUTSIDE A DIGEST IS ITSELF OUTSIDE THAT DIGEST,
# > AND ONLY A PERSON WILL EVER NOTICE IT HAS GONE STALE.***
UNBOUND_FIELDS = ("recorded timestamp", "submitter attribution", "ledger ordinal",
                  "the plan seal's signature and era")


class CanonicalEnvelopeFormError(Exception):
    def __init__(self, rule: str, detail: str) -> None:
        self.rule = rule
        self.detail = detail
        super().__init__(f"{rule}: {detail}")


def _is_sha256_hex(s: Any) -> bool:
    return (
        isinstance(s, str)
        and len(s) == 64
        and all(c in "0123456789abcdef" for c in s)  # CF-HASH-001: LOWERCASE hex
    )


def envelope_canonical_form(
    *,
    envelope_kind: str,
    payload_hash: str,
    position: int,
    prev_envelope_hash: str,
    is_genesis: bool,
) -> dict:
    """Build and validate the five-entry mapping of §2.

    `is_genesis` is REQUIRED and must be supplied by the caller.

     RULED by `ERR-P3-001`, adopting this implementation's
    resolution verbatim: **an implementation MUST NOT infer genesis from the
    envelope form alone. Genesis is an input to canonicalisation, supplied by
    the caller from the sequence's own state, and an implementation that cannot
    obtain it MUST refuse rather than guess.**

    The finding behind it: CEF-007 makes the relationship a biconditional that
    "MUST be enforced in BOTH directions", yet the leaf carries no predicate for
    genesis other than `prev_envelope_hash` itself, so the check would be
    testing a value against itself. `CEF-007` is now scoped to whoever
    *constructs* an envelope, where the sequence position is known; it never
    could bind a verifier holding one envelope in isolation.
    """
    if not isinstance(envelope_kind, str):
        raise CanonicalEnvelopeFormError("CEF-001", "envelope_kind must be a string")
    if not _is_sha256_hex(payload_hash):
        raise CanonicalEnvelopeFormError(
            "CEF-001", "payload_hash must be 64 lowercase hex digits"
        )
    if isinstance(position, bool) or not isinstance(position, int):
        raise CanonicalEnvelopeFormError("CEF-001", "position must be an integer")
    if position < 0:
        # RULED by `ERR-P3-002`: `position` is ZERO-BASED; the
        # first envelope in a request's sequence has position 0. Two
        # implementations disagreeing here produce different leaf bytes for the
        # same record, which is exactly what a canonical form exists to prevent.
        raise CanonicalEnvelopeFormError(
            "CEF-001", "position is zero-based and must not be negative")

    if prev_envelope_hash in FORBIDDEN_PREV_HASHES:
        # A-10: CEF-008 forbids CHOOSING that value as the sentinel. It does
        # not, in terms, tell a verifier what to do on ENCOUNTERING it. Since
        # CEF-001 guarantees a predecessor's canonical form is never empty
        # bytes, SHA256_OF_EMPTY can never legitimately arise — so it is
        # refused here, and the interpretive step is recorded.
        raise CanonicalEnvelopeFormError(
            "CEF-008", f"prohibited sentinel/digest {prev_envelope_hash[:12]}... (A-10)"
        )

    if is_genesis:
        if prev_envelope_hash != GENESIS_SENTINEL:  # CEF-006 / CEF-007 ->
            raise CanonicalEnvelopeFormError(
                "CEF-007", "genesis envelope claims a predecessor that does not exist"
            )
    else:
        if prev_envelope_hash == GENESIS_SENTINEL:  # CEF-007 <-
            # "The second is the dangerous one, because nothing about the
            # resulting bytes looks wrong."
            raise CanonicalEnvelopeFormError(
                "CEF-007", "non-genesis envelope carries the sentinel and detaches from the chain"
            )
        if not _is_sha256_hex(prev_envelope_hash):
            raise CanonicalEnvelopeFormError(
                "CEF-004", "prev_envelope_hash must be 64 lowercase hex digits"
            )

    return {
        "canonical_envelope_form_version": CEF_VERSION,
        "envelope_kind": envelope_kind,
        "payload_hash": payload_hash,
        "position": position,
        "prev_envelope_hash": prev_envelope_hash,
    }


def envelope_canonical_bytes(**kwargs: Any) -> bytes:
    """CEF-002. The canonical bytes are produced by applying the Boundry
    Canonical Form to the five-entry mapping. This form introduces NO new
    emission rules."""
    return canonical_bytes(envelope_canonical_form(**kwargs))


def envelope_leaf_hash(**kwargs: Any) -> str:
    """CEF-004's input for the NEXT envelope: the lowercase hex SHA-256 of this
    envelope's canonical form."""
    return hashlib.sha256(envelope_canonical_bytes(**kwargs)).hexdigest()


def verify_chain_links(envelopes: list[dict]) -> list[str]:
    """CEF-004: every link is SHA-256, end to end. Altering any field of any
    earlier envelope changes its canonical form, changes its hash, and breaks
    every link that follows.

    Each element is a dict of the five constructor arguments except
    `prev_envelope_hash`/`is_genesis`, which are derived and checked here.
    Returns the list of leaf hashes; raises on the first broken link.

    This establishes ONLY that the supplied sequence is internally linked. It
    establishes nothing about whether the sequence is complete, whether it is
    the chain the operator holds, or who signed anything.
    """
    leaves: list[str] = []
    expected_prev = GENESIS_SENTINEL
    for i, env in enumerate(envelopes):
        stated = env.get("prev_envelope_hash", expected_prev)
        if stated != expected_prev:
            raise CanonicalEnvelopeFormError(
                "CEF-004", f"link broken at index {i}: stated predecessor does not match"
            )
        leaf = envelope_leaf_hash(
            envelope_kind=env["envelope_kind"],
            payload_hash=env["payload_hash"],
            position=env["position"],
            prev_envelope_hash=expected_prev,
            is_genesis=(i == 0),
        )
        leaves.append(leaf)
        expected_prev = leaf
    return leaves
