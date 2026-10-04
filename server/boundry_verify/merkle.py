"""`merkle-rfc6962-sha256-cef1` — the head construction named by CP-015.

CP-015 denotes exactly:
  leaves    = SHA-256(0x00 || canonical envelope form bytes)
  interior  = SHA-256(0x01 || left || right)
  tree      per RFC 6962 §2.1, splitting at the LARGEST POWER OF TWO STRICTLY
            LESS THAN n
  the duplicate-last-node variant is EXCLUDED BY NAME — it admits two
  different leaf sequences producing one root.

CP-003: a verifier MUST NOT assume a construction; it MUST read
`head_construction_id` and apply the named one. The identifier is carried as
data — no call site hard-codes it. `CONSTRUCTIONS` is that lookup.
"""

from __future__ import annotations

import hashlib

__all__ = [
    "MerkleError", "CONSTRUCTION_ID", "CONSTRUCTIONS",
    "leaf_hash", "interior_hash", "merkle_tree_hash",
    "verify_inclusion", "verify_consistency",
]

CONSTRUCTION_ID = "merkle-rfc6962-sha256-cef1"

LEAF_PREFIX = b"\x00"
INTERIOR_PREFIX = b"\x01"


class MerkleError(Exception):
    """CP-016: a proof verifier MUST signal failure by raising, never by
    returning a falsy value a caller can forget to check. Failure to verify
    MUST be distinguishable from an unattempted verification."""


def leaf_hash(cef_bytes: bytes) -> bytes:
    """SHA-256(0x00 || canonical envelope form bytes).

    The 0x00/0x01 domain separation is "the substance of the identifier, not a
    detail of it": without it, a leaf whose data is the concatenation of two
    child hashes hashes identically to the interior node above them, so a leaf
    can be presented as an interior node and the reverse.
    """
    return hashlib.sha256(LEAF_PREFIX + cef_bytes).digest()


def interior_hash(left: bytes, right: bytes) -> bytes:
    """SHA-256(0x01 || left || right).

    BV-031 limb 1, ported here. ⚠ This was ABSENT until
    31 Aug 2026: it accepted a 31-byte left and returned a digest, while the
    producer refused the same input by name. Limb 1 was ported to
    `merkle_tree_hash` and NOT to this function, because that pack was scoped
    to the defect that had been OBSERVED -- and an agreement sweep found
    this one deliberately, on its first run.

    The same rule, in a third context: an exclusion that enumerates instances is
    a snapshot of what the author happened to think of. So is a REPAIR.
    """
    if not isinstance(left, (bytes, bytearray)) or not isinstance(right, (bytes, bytearray)):
        raise MerkleError(
            "interior nodes combine two 32-byte digests; got "
            f"{type(left).__name__} and {type(right).__name__}")
    if len(left) != 32 or len(right) != 32:
        raise MerkleError(
            f"interior nodes combine two 32-byte digests; got {len(left)} and {len(right)}")
    return hashlib.sha256(INTERIOR_PREFIX + left + right).digest()


def _split(n: int) -> int:
    """The largest power of two STRICTLY LESS THAN n (RFC 6962 §2.1).

    The STOP-A mutation set moved this by one and 52 tests failed, which is the
    measure of how much depends on the boundary being unambiguous.
    """
    if n < 2:
        raise MerkleError("split is undefined for n < 2")
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def _checked_split(n: int) -> int:
    """`_split` with its PROGRESS guarantee enforced at the call site.

    > **⚠ What this is, and what it is NOT (`BV-022`).**
    > This is a **per-step monotone-decrease invariant**, and that is all it is.
    > It is **not** `BV-022`, it does **not** terminate by exhaustion, and it is
    > **not** an internal cap. *`BV-022` is a property of a WALK; this is a
    > property of one STEP of one.*
    >
    > `BV-022` asks for two things, and `verify_inclusion` gets them from two
    > different lines. **This guard supplies the first half only:** because
    > `0 < k < n`, both descent branches strictly shrink `size`, so the descent
    > is bounded by `ceil(log2(tree_size))` — and `tree_size` is read from
    > SIGNED bytes. **The second half — refusing an over-long proof BEFORE
    > walking it — is the `len(audit_path) != len(decisions)` check**, which
    > predates this pack. *Neither line is `BV-022` on its own.*

    > **⚠ Added from a mutation that had been scored as killed
    > for a day and a half.** `M06` moves the split to the largest power of two
    > **<= n**, so for a power-of-two `n` it returns `n` itself: the recursion
    > stops shrinking and the verifier never returns. **`T-3` added a probe
    > timeout when that first happened — and the timeout was then swallowed,
    > because `_Timeout` derived from `Exception` and every probe catches
    > broadly.** The hang was reported as `KILLED`.
    >
    > ***A verifier that does not terminate has not returned a verdict.***
    > Rather than rely on a timeout to notice, the split's contract is checked
    > where it is used: **a construction that does not make progress is REFUSED.**
    > The guard lives here and not inside `_split`, so that mutating `_split` —
    > which is the point of `M06` — still meets it.
    >
    > `merkle_tree_hash` already carried this check inline, added at `T-3` when
    > `M06` first hung. **`verify_inclusion`'s descent did not**, which is where
    > the surviving hang lived.
    """
    k = _split(n)
    if not 0 < k < n:
        raise MerkleError(
            f"the construction's split returned {k} for n={n}; RFC 6962 requires "
            "0 < k < n, and a split that does not shrink the range would recurse "
            "without end. Refusing rather than not terminating")
    return k


def _assert_leaf_hashes(leaves: list[bytes], where: str) -> None:
    """BV-031 limb 1, ported to the verifier.

    ⚠ This was ABSENT here until 31 Aug 2026. `merkle_tree_hash` returned
    `leaves[0]` unchecked for n == 1 — the one case the recursion never
    reaches — so a 6-byte value passed straight through AS A ROOT. The
    producer closed this; the verifier was left untouched to preserve
    X-07's pin, and the pin protected a measurement while freezing the defect
    into the artefact it was protecting.

    This is the STANDALONE artefact handed to bundle consumers. It is the
    thing an outside party runs.
    """
    for i, leaf in enumerate(leaves):
        if not isinstance(leaf, (bytes, bytearray)) or len(leaf) != 32:
            got = (f"{len(leaf)} bytes" if isinstance(leaf, (bytes, bytearray))
                   else type(leaf).__name__)
            raise MerkleError(
                f"{where}: element {i} is {got}; this entry point takes LEAF "
                "HASHES -- 32-byte SHA-256 digests produced by leaf_hash() -- "
                "and refuses anything else rather than truncating, padding or "
                "hashing it for you")


def _mth(leaves: list[bytes]) -> bytes:
    """MTH(D[n]) per RFC 6962 §2.1, over ALREADY-VALIDATED leaf hashes."""
    n = len(leaves)
    if n == 0:
        # ⚠ RFC 6962 §2.1 line 221: MTH({}) = SHA-256(). CONFORMANT since
        # This function REFUSED until 31 Aug 2026, citing CP-014
        # and CEF-008. Both clauses are real; neither reaches here:
        #
        #   CP-014 binds an EMITTER at the CHECKPOINT layer, and ¶63 says of
        #   the primitive and the sentinel that "both are correct in their own
        #   role, AND NEITHER SHOULD CHANGE" -- locating the hazard with "the
        #   emitter that would act on it". The refusal was that clause applied
        #   to the side the clause exempts by name.
        #
        #   CEF-008 forbids this digest AS THE GENESIS SENTINEL -- a role in
        #   the envelope form -- not as MTH's output.
        #
        # The refusal belongs at checkpoint emission, where CP-014 puts it,
        # and at checkpoint VERIFICATION, which CP-014 does not yet cover:
        # see CP-014-V (DRAFT) and `checkpoint.py`.
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _split(n)
    if not 0 < k < n:
        # ⚠ Found by mutation M06 at T-3: a split that fails to make progress
        # recurses for ever, and the campaign HUNG rather than reporting a
        # result. A verifier must fail, not hang — a hang is indistinguishable
        # from a slow answer and cannot be reported as a verdict.
        raise MerkleError(f"split made no progress: k={k} for n={n}")
    return interior_hash(_mth(leaves[:k]), _mth(leaves[k:]))


def merkle_tree_hash(leaves: list[bytes]) -> bytes:
    """MTH over already-hashed leaves. RFC 6962 §2.1.

    Refuses any element that is not exactly 32 bytes (BV-031 limb 1).

    ⚠ AND THE LIMIT THAT NO CHECK CLOSES (BV-031 limb 2):

    > A 32-BYTE VALUE THAT IS NOT A LEAF HASH IS INDISTINGUISHABLE FROM ONE
    > THAT IS.

    A SHA-256 digest has no structure to inspect. What is refused here is the
    SHAPE; the PROVENANCE of a correctly-shaped digest is the caller's
    obligation and is enforced nowhere. Do not read the check above as
    enforcement of the leaf contract.

    The empty tree returns SHA-256("") per RFC 6962 — see `_mth`.
    """
    _assert_leaf_hashes(leaves, "merkle_tree_hash")
    return _mth(leaves)


def verify_inclusion(leaf: bytes, leaf_index: int, tree_size: int,
                     audit_path: list[bytes], root: bytes) -> None:
    """RFC 6962 §2.1.1. Raises MerkleError on any failure (CP-016).

    `tree_size` MUST equal the `ledger_ordinal` of the checkpoint being proved
    against; `checkpoint.py` enforces that equality.

    **`BV-022` holds here, and it takes two lines to hold.** The descent below
    walks `size`, which starts at `tree_size` — read from signed bytes — and
    never touches `audit_path`; `_checked_split` is what makes that descent
    shrink. **Only then is `len(audit_path)` compared to the length the tree
    admits, so an over-long path is REFUSED BEFORE IT IS WALKED.** *Measured
    with a path whose elements raise if touched: they are never touched.*

    The audit path is ordered **leaf-to-root** (RFC 6962's PATH concatenates the
    recursive part first, so element 0 is the deepest sibling). The descent
    below records the left/right decisions top-down and then folds them in
    reverse, because a proof cannot be checked purely top-down: each level's
    sibling combines with a node that is only known after descending.
    """
    if tree_size <= 0:
        raise MerkleError("tree_size must be positive (CP-014)")
    if not 0 <= leaf_index < tree_size:
        # CP-012: ledger_ordinal is a COUNT, not an index. A checkpoint at
        # ledger_ordinal = 7 commits to leaves 0..6 inclusive.
        raise MerkleError(f"leaf_index {leaf_index} outside [0, {tree_size})")

    decisions = []
    index, size = leaf_index, tree_size
    while size > 1:
        k = _checked_split(size)
        if index < k:
            decisions.append(True)          # node is in the LEFT subtree
            size = k
        else:
            decisions.append(False)         # node is in the RIGHT subtree
            index -= k
            size -= k

    if len(audit_path) != len(decisions):
        raise MerkleError(
            f"audit path has {len(audit_path)} element(s); the tree requires "
            f"{len(decisions)} for leaf {leaf_index} of {tree_size}"
        )

    node = leaf
    for is_left, sibling in zip(reversed(decisions), audit_path):
        if len(sibling) != 32:
            raise MerkleError("audit path element is not a 32-byte digest")
        node = interior_hash(node, sibling) if is_left else interior_hash(sibling, node)
    if node != root:
        raise MerkleError("inclusion proof does not reach the stated root")


def _expected_consistency_proof_len(old_size: int, new_size: int) -> int:
    """`BV-022` — the exact element count RFC 6962 §2.1.2 admits, from the two
    tree sizes ALONE. **Both are read from signed bytes; the proof is not
    consulted.** That is what makes the bound trustworthy enough to refuse on.

    > **⚠ Added because `verify_consistency` did NOT satisfy
    > `BV-022` and `verify_inclusion` did.** Measured, not assumed: an over-long
    > consistency proof was **WALKED** — its first element consumed and hashed
    > before any length was checked, the surplus noticed only by the trailing
    > `if path:` — and an under-long one was discovered by **EXHAUSTION**, the
    > `"consistency path exhausted"` branch. ***Both are exactly the mechanisms
    > `BV-022` names and forbids.***

    The counting mirrors the walk below step for step, deliberately: a bound
    derived independently could disagree with the walk it is meant to bound, and
    the disagreement would be silent. The two loops below re-check it.
    """
    node, last_node = old_size - 1, new_size - 1
    while node & 1:
        node >>= 1
        last_node >>= 1
    count = 1 if node else 0        # the `first` element; implicit when node == 0
    while node:
        if node & 1:
            count += 1
        elif node < last_node:
            count += 1
        node >>= 1
        last_node >>= 1
    while last_node:
        count += 1
        last_node >>= 1
    return count


def verify_consistency(old_size: int, new_size: int, old_root: bytes,
                       new_root: bytes, proof: list[bytes]) -> None:
    """RFC 6962 §2.1.2. Raises on failure (CP-016).

    "This is the proof that makes append-only checkable by a third party rather
    than merely asserted" — without it, an operator holding two witnessed
    checkpoints could have forked between them and no holder of both could tell.
    """
    if old_size < 0 or new_size < 0:
        raise MerkleError("tree sizes must be non-negative")
    if old_size > new_size:
        raise MerkleError(f"old_size {old_size} exceeds new_size {new_size}")
    if old_size == new_size:
        if proof:
            raise MerkleError("consistency proof for equal sizes must be empty")
        if old_root != new_root:
            # CP-017: same size, different root.
            raise MerkleError("equal tree sizes with different roots (CP-017: equivocation)")
        return
    if old_size == 0:
        raise MerkleError("consistency from an empty tree is not defined here (CP-014)")

    # BV-022: bounded by signed sizes, and REFUSED BEFORE IT IS WALKED.
    expected = _expected_consistency_proof_len(old_size, new_size)
    if len(proof) != expected:
        raise MerkleError(
            f"consistency proof has {len(proof)} element(s); sizes {old_size} -> "
            f"{new_size} admit exactly {expected}. Refused before the walk")
    for element in proof:
        if not isinstance(element, (bytes, bytearray)) or len(element) != 32:
            # verify_inclusion checked this per element DURING its fold; here it
            # is part of the gate, so no attacker-supplied value reaches a hash
            # before its shape is known.
            raise MerkleError("consistency proof element is not a 32-byte digest")

    path = list(proof)

    node, last_node = old_size - 1, new_size - 1
    # Rise to the highest subtree whose right edge is the old tree's right edge.
    while node & 1:
        node >>= 1
        last_node >>= 1

    if node:
        first = path.pop(0)
    else:
        # old_size is an exact power of two: the first node is implicit.
        first = old_root
    node_old = node_new = first

    while node:
        if node & 1:
            if not path:
                raise MerkleError(
                    "BOUND DISAGREES WITH WALK: the bound under-counted for "
                    "these sizes; a bound and the walk it guards must agree")
            sib = path.pop(0)
            node_old = interior_hash(sib, node_old)
            node_new = interior_hash(sib, node_new)
        elif node < last_node:
            if not path:
                raise MerkleError(
                    "BOUND DISAGREES WITH WALK: the bound under-counted for "
                    "these sizes; a bound and the walk it guards must agree")
            node_new = interior_hash(node_new, path.pop(0))
        node >>= 1
        last_node >>= 1

    while last_node:
        if not path:
            raise MerkleError(
                "BOUND DISAGREES WITH WALK: the bound under-counted for "
                "these sizes; a bound and the walk it guards must agree")
        node_new = interior_hash(node_new, path.pop(0))
        last_node >>= 1

    if path:
        raise MerkleError(
            f"BOUND DISAGREES WITH WALK: {len(path)} element(s) unconsumed; "
            "_expected_consistency_proof_len over-counted for these sizes")
    if node_old != old_root:
        raise MerkleError("consistency proof does not reproduce the earlier root")
    if node_new != new_root:
        raise MerkleError("consistency proof does not reproduce the later root")


# CP-003 / CP-015: carried as data. A verifier reads head_construction_id and
# looks it up here; an unrecognised value means STOP, never a fallback.
#: ⚠ **THE RULE-NAMING IDENTIFIER**: *the leaf is
#: the hash of the canonical envelope form the record itself declares; a record
#: carrying no declaration is v1 by `D1-c`.* `…-cef3` is refused by that ruling:
#: a version token on a version-agnostic construction is a trap
#: pre-built.
CONSTRUCTION_ID_AS_DECLARED = "merkle-rfc6962-sha256-cef-as-declared"

#: ⚠ **BOTH IDENTIFIERS MAP TO THE SAME FUNCTIONS, AND THAT IS THE PROOF THAT
#: THE SECOND NAMES A RULE AND NOT A DIFFERENT ALGORITHM.** Nothing about the
#: leaf, interior, tree hash, inclusion or consistency computation changes with
#: the envelope form; what changes is which form produced the preimage, and the
#: record declares that itself.
#:
#: ⚠ **`…-cef1` IS NEVER REMOVED.** Every checkpoint that carries it is still
#: true, and a verifier that dropped it would strand every receipt ever issued
#: — `BV-028`'s territory, and the reason a ruling keeps both.
CONSTRUCTIONS = {
    CONSTRUCTION_ID: {
        "leaf_hash": leaf_hash,
        "interior_hash": interior_hash,
        "merkle_tree_hash": merkle_tree_hash,
        "verify_inclusion": verify_inclusion,
        "verify_consistency": verify_consistency,
    },
    CONSTRUCTION_ID_AS_DECLARED: {
        "leaf_hash": leaf_hash,
        "interior_hash": interior_hash,
        "merkle_tree_hash": merkle_tree_hash,
        "verify_inclusion": verify_inclusion,
        "verify_consistency": verify_consistency,
    },
}
