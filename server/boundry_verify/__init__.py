"""An independent Boundry verifier, written from the ratified specifications alone.

The author of this package has not read the Boundry kernel, its tests,
its conformance corpora or its golden vectors. **Standard library only,
WITH ONE DECLARED INJECTION-SEAM FALLBACK; no network; no third-party package** —
Ed25519 is implemented from RFC 8032 §5.1.7, because the verifier must run where
nothing can be installed.

⚠ **STANDARD LIBRARY ONLY, WITH NO DECLARED INJECTION-SEAM FALLBACK — AND THE
RECORD OF THE ONE THERE WAS.** Two modules DID import
`compiler.determinism.canonical` inside a function body,
and only when no `canonicalise` is injected — an injection seam with a default
(whose own first version claimed too much and was refuted by
measurement). **The permitted set lives in
`VERIFIER/testing/verifier_imports.DECLARED_NON_STDLIB_IMPORTS`**, is a governed
vocabulary with a register row, and names the FILES each entry is permitted in.

⚠ *"Standard library only" on its own was PROSE, and it overstated the tree.*
It is measured now, from SOURCE, by `selftest_rsa_pkcs1.check_stdlib_only` —
because the loaded-module walk that used to be the whole check **cannot see an
import written inside a function**, which is where both real sites are.

  T-1  canonical form · bodies · identifier derivation · canonical envelope form
  T-2  Ed25519 · key directory · Merkle construction · checkpoints · the chain
       and the verdict ladder
  T-3  mutation acceptance — 25/25 killed by 37 probes, all controls passing
  +    ERRATA_P3_02 applied: the five-key receipt form, the witness signature
       scope, and ERR-P3-008's four-outcome verdict vocabulary

⚠ The checkpoint and receipt rungs are exercised against SYNTHETIC material
only. Nothing has been witnessed and no checkpoint has ever been emitted into a
chain. No result from this package may be reported as verifying production data.

⚠ There is no signing primitive here, deliberately. A verifier that can sign is
a verifier that can manufacture the evidence it checks.
"""

# ⚠⚠ **THE DECLARED INTERPRETER FLOOR, FIRST ACT — AND FIRST MEANS FIRST.**
# Every import below this line can be newer than
# the floor: `.bodies` defines `IdentifierKind(enum.StrEnum)`, which is 3.11+,
# so a guard placed after it never runs — the package dies with an
# `AttributeError` about `enum` and the reader is told nothing about floors.
#
# Measured on 3.9.6: 32 of the package's 44 modules fail to import, and the
# shipped self-tests still print `OK (skipped=11)`.
#
# > ***A GUARD THAT RUNS SECOND IS NOT A GUARD. IT IS A COMMENT THAT HAPPENS
# > TO BE TRUE MOST OF THE TIME.***
from .interpreter_floor import assert_floor as _assert_floor  # noqa: E402

_assert_floor()

from .canonical_form import (  # noqa: F401
    CanonicalFormError, canonicalise, canonical_bytes, content_hash,
    SEAL_PROFILE, FULL_PROFILE, has_nfc_key_collision,
)
from .envelope_form import (  # noqa: F401
    CanonicalEnvelopeFormError, envelope_canonical_form, envelope_canonical_bytes,
    envelope_leaf_hash, verify_chain_links, CEF_KEYS, FORBIDDEN_PREV_HASHES,
)
from .bodies import (  # noqa: F401
    sealed_plan_body, intent_body, request_body, legacy_chain_head,
    derive_intent_id, derive_envelope_id, NAMESPACES,
)
from .ed25519 import verify as ed25519_verify, Ed25519Error  # noqa: F401
from .keys import KeyDirectory, KeyDirectoryError, parse_public_key  # noqa: F401
from .key_forms import (  # noqa: F401
    KeyFormError, REDUCIBLE_FORMATS, reduce_to_ed25519,
    REFUSALS as KEY_FORM_REFUSALS,
)
from .merkle import (  # noqa: F401
    MerkleError, CONSTRUCTION_ID, CONSTRUCTIONS, leaf_hash, interior_hash,
    merkle_tree_hash, verify_inclusion, verify_consistency,
)
from .checkpoint import (  # noqa: F401
    CheckpointError, CheckpointStatement, CHECKPOINT_KEYS,
    verify_checkpoint_signature, assert_era_entitled_to_time,
    verify_checkpoint, detect_equivocation, resolve_construction,
    witness_message,
)
from .receipt import Receipt, ReceiptError, RECEIPT_KEYS  # noqa: F401
from .signature_form import (  # noqa: F401
    SignatureFormError, ED25519_CANONICAL_V1, THIS_ERA_SIGNATURE_FORM,
    CONSTRUCTIONS as SIGNATURE_CONSTRUCTIONS,
)
from .verdict import (  # noqa: F401
    Verdict, VerdictError, Report, Outcome, ATTESTED, UNATTESTED, REFUTED, ALTERED,
    receipt_verdict, unwitnessed_verdict,
)
from .chain import verify_record, SYNTHETIC_RUNGS  # noqa: F401

__all__ = [n for n in dir() if not n.startswith("_")]
