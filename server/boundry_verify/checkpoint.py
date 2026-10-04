"""Checkpoints, from the checkpoints-and-receipts specification alone.

⚠ **WHAT THIS MODULE HAS ACTUALLY SEEN, STATED EXACTLY**
(correcting the line it replaces).

  * It VERIFIES checkpoints. It emits none and signs none.
  * Canon's vectors exercise it on SYNTHETIC material, and that remains the bulk
    of what it has met.
  * ⚠ **ONE REAL CHECKPOINT HAS PASSED THROUGH IT** — signed by a real Ed25519
    key over a real twelve-leaf ledger in a measured run, and verified from
    a directory holding no private key.
  * **NOTHING HAS BEEN INDEPENDENTLY WITNESSED.** No party other than the
    operator has seen any head this module has checked, so every witness rung it
    has reported is `UNATTESTED`.

⚠ **THE LINE THIS REPLACES SAID "Every checkpoint this module handles is
synthetic test material", AND THAT RUN MADE THAT UNTRUE.** It was
true when it was written and stopped being true without anyone editing it.

> ***A STATUS LINE IS A CLAIM LIKE ANY OTHER, AND THE ONE THING IT CANNOT DO IS
> STAY CORRECT BY ITSELF.***

No code in this module changed, then or now. **No result from it may be reported
as an independently witnessed one**, which is the part of the old warning that
was always the point.
"""

from __future__ import annotations

from typing import Any, Mapping

from .canonical_form import canonical_bytes
from .ed25519 import verify as ed25519_verify
from .keys import KeyDirectory
from .merkle import CONSTRUCTIONS, MerkleError

__all__ = ["CheckpointError", "CHECKPOINT_KEYS", "CheckpointStatement",
           "verify_checkpoint_signature", "assert_era_entitled_to_time",
           "verify_checkpoint", "detect_equivocation", "resolve_construction",
           "witness_message"]

CHECKPOINT_VERSION = 1

# CP-011: the field set is FIXED AND CLOSED, exactly as CEF-001 closes the
# leaf's. Exactly these six keys, always. None optional, none ever omitted.
CHECKPOINT_KEYS = (
    "checkpoint_version",
    "era",
    "head_construction_id",
    "head_hash",
    "kernel_time",
    "ledger_ordinal",
)


class CheckpointError(Exception):
    pass


def _is_sha256_hex(s: Any) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


class CheckpointStatement:
    """The six-field statement of §2."""

    def __init__(self, statement: Mapping[str, Any]) -> None:
        missing = [k for k in CHECKPOINT_KEYS if k not in statement]
        extra = [k for k in statement if k not in CHECKPOINT_KEYS]
        if missing or extra:
            raise CheckpointError(
                f"CP-011: field set is closed; missing={missing} unexpected={extra}"
            )
        self.raw = dict(statement)
        self.checkpoint_version = statement["checkpoint_version"]
        self.ledger_ordinal = statement["ledger_ordinal"]
        self.head_hash = statement["head_hash"]
        self.head_construction_id = statement["head_construction_id"]
        self.era = statement["era"]
        self.kernel_time = statement["kernel_time"]

        if self.checkpoint_version != CHECKPOINT_VERSION:
            # CP-011: any change to the field set or a field's meaning is a NEW
            # checkpoint_version, never an in-place amendment.
            raise CheckpointError(
                f"unknown checkpoint_version {self.checkpoint_version!r}; this "
                "verifier will not guess a field set"
            )
        if isinstance(self.ledger_ordinal, bool) or not isinstance(self.ledger_ordinal, int):
            raise CheckpointError("ledger_ordinal must be an integer")
        if self.ledger_ordinal < 1:
            # CP-014, closing finding F-P2-2. An empty tree's RFC 6962 root is
            # SHA-256("") — byte for byte the digest CEF-008 forbids — and is
            # "indistinguishable from a broken implementation that hashed
            # nothing". Checkpointing it would convert the one signal that
            # reveals total canonicalisation failure into signed, witnessed
            # evidence of correctness.
            raise CheckpointError("CP-014: ledger_ordinal MUST be >= 1; an empty tree is never checkpointed")
        if not _is_sha256_hex(self.head_hash):
            raise CheckpointError("head_hash must be 64 lowercase hex digits")
        if not isinstance(self.kernel_time, int) or isinstance(self.kernel_time, bool):
            raise CheckpointError("kernel_time must be an integer (microseconds since epoch)")

    def canonical_bytes(self) -> bytes:
        """CP-001: canonicalised and signed
        with the era's key."""
        return canonical_bytes(self.raw)

    # CP-002: kernel_time is the OPERATOR'S ASSERTION and carries no independent
    # weight. Time trust comes from the witness, never from this field.
    @property
    def operator_asserted_time(self) -> int:
        return self.kernel_time

    def commits_to_leaf_range(self) -> range:
        """CP-012: ledger_ordinal is a COUNT (RFC 6962 tree_size), not an index.
        A checkpoint at ledger_ordinal = 7 commits to leaves 0..6 inclusive."""
        return range(0, self.ledger_ordinal)

    def assert_not_self_committing(self, own_leaf_index: int) -> None:
        """CP-013: the checkpoint's own sealed record MUST be assigned a leaf
        index >= ledger_ordinal. A checkpoint MUST NOT be included in the tree
        it commits to — otherwise the head depends on a statement that depends
        on the head."""
        if own_leaf_index < self.ledger_ordinal:
            raise CheckpointError(
                f"CP-013: checkpoint's own leaf index {own_leaf_index} is inside the "
                f"tree it commits to (ledger_ordinal={self.ledger_ordinal})"
            )


def resolve_construction(statement: CheckpointStatement) -> dict:
    """CP-003: a verifier MUST NOT assume a construction; it MUST read
    `head_construction_id` and apply the named one. **If it is unrecognised,
    STOP — do not fall back to an assumed one** (§8 step 3)."""
    try:
        return CONSTRUCTIONS[statement.head_construction_id]
    except KeyError:
        raise CheckpointError(
            f"CP-003: unrecognised head_construction_id "
            f"{statement.head_construction_id!r} — stopping. This verifier will "
            "not fall back to an assumed construction."
        ) from None


def verify_checkpoint_signature(statement: CheckpointStatement, signature: bytes,
                                directory: KeyDirectory) -> bool:
    """§8 steps 1-2: resolve the era key from the directory, obtained
    independently, then check the signature over the canonical bytes."""
    key = directory.resolve(statement.era)
    return ed25519_verify(key.public_key, statement.canonical_bytes(), signature)


def assert_era_entitled_to_time(statement: CheckpointStatement,
                                directory: KeyDirectory) -> None:
    """`KD-013`: refuse unless the era's window contains the statement's time.

    ⚠⚠ **THIS IS A CONSISTENCY CHECK AND NOT TIME EVIDENCE, AND `CP-002`
    ALREADY SAYS WHY.** `kernel_time` is *the OPERATOR'S ASSERTION and carries
    no independent weight*; the directory's windows are the operator's
    declaration too. Comparing them asks whether the signer's own two
    statements agree — which catches a retired key signing a later instant AS
    CLAIMED, the case `C.7` names, and does NOT catch a signer who moves both.

    > ***TWO STATEMENTS BY THE SAME PARTY AGREEING IS CONSISTENCY, NOT
    > CORROBORATION. TIME TRUST COMES FROM THE WITNESS.***

    Stating that is the point. A check of this kind presented as proof of when
    something happened would be worse than no check, because it would look like
    the witness rung is already covered when it is not.
    """
    directory.resolve_at(statement.era, statement.kernel_time)


def verify_checkpoint(statement: CheckpointStatement, signature: bytes,
                      directory: KeyDirectory) -> bool:
    """***THE CALLABLE A CALLER REACHES FOR.*** Signature AND entitlement.

    ⚠ **TWO QUESTIONS, AND KEEPING THEM SEPARATE IS DELIBERATE.**
    `verify_checkpoint_signature` answers *did this key sign these bytes* — a
    fact about cryptography, involving no assertion by anybody.
    `assert_era_entitled_to_time` answers *was this key entitled to that
    instant* — a fact about two declarations agreeing. Fusing them would let a
    `False` mean either, and the earlier lesson runs the other way here: what is
    made structural is that the ENTRY POINT asks both, not that the two
    questions become one.

    ⚠ The entitlement is checked FIRST. A signature that verifies under a key
    which had no business signing that instant is the more misleading of the
    two outcomes to report on its own.
    """
    assert_era_entitled_to_time(statement, directory)
    return verify_checkpoint_signature(statement, signature, directory)


def witness_message(statement: CheckpointStatement) -> bytes:
    """`ERR-P3-004`: **a witness attests to SHA-256 over the checkpoint
    statement's canonical bytes.** That digest, and nothing else, is the value
    presented to a timestamp authority or committed to a transparency log — and
    it closes the gap where §8 step 6 said "verify the receipt" without saying
    over what.

    `ERR-P3-007` — RULED: the attested value is the **raw 32
    bytes** of the SHA-256, never its 64-character hexadecimal text. Hex appears
    only where a value is carried inside a canonical-form document
    (`attested_digest`); what a verifier checks a signature over is the binary
    digest. Mutation M17 flips this to hex and is killed, so the choice is
    pinned rather than assumed.
    """
    import hashlib as _h
    return _h.sha256(statement.canonical_bytes()).digest()


def detect_equivocation(a: CheckpointStatement, b: CheckpointStatement) -> str | None:
    """CP-017. Two checkpoints in the same era and construction with the same
    `ledger_ordinal` and different `head_hash` are EVIDENCE OF EQUIVOCATION, and
    `ledger_ordinal` MUST be non-decreasing over time within an era and
    construction.

    "A verifier holding both statements needs nothing from us to draw that
    conclusion, which is the entire point of putting them in others' hands."
    """
    if a.era != b.era or a.head_construction_id != b.head_construction_id:
        return None
    if a.ledger_ordinal == b.ledger_ordinal and a.head_hash != b.head_hash:
        return (f"CP-017 EQUIVOCATION: two checkpoints in era {a.era!r} at "
                f"ledger_ordinal {a.ledger_ordinal} carry different head_hash values")
    earlier, later = (a, b) if a.kernel_time <= b.kernel_time else (b, a)
    if later.ledger_ordinal < earlier.ledger_ordinal:
        return (f"CP-017: ledger_ordinal decreased within era {a.era!r} "
                f"({earlier.ledger_ordinal} -> {later.ledger_ordinal})")
    return None
