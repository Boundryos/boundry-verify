"""What is hashed (§6) and identifier derivation (§7), from
the canonical-form specification alone.

§6 answers *which* value is canonicalised. The specification's own warning
applies: getting this wrong is the most common way to produce correct bytes
for the wrong thing.
"""

from __future__ import annotations

import enum as _enum
import uuid as _uuid
from typing import Any, Mapping, Sequence

from .canonical_form import canonical_bytes, canonicalise, content_hash

__all__ = [
    "sealed_plan_body", "intent_body", "request_body",
    "derive_intent_id", "derive_micro_contract_id", "derive_composition_id",
    "derive_envelope_id", "derive_request_internal_id",
    "legacy_chain_head", "NAMESPACES", "IdentifierKind", "UNBOUND_ENVELOPE_FIELDS",
]

# CF-SEAL-001 — removed unconditionally; these are what the seal produces.
_SEAL_PRODUCED_FIELDS = ("content_hash", "sealed_at", "signature")

# §6.3 — a table, not a rule. "Version 1 has no general rule for absent
# optional fields." Treated as exhaustive, per the spec's own instruction not
# to reason from the pattern that explains it.
_OMIT_WHEN_ABSENT_TOP = ("check_refs", "query_spec", "bcl_version")
_NULL_WHEN_ABSENT_TOP = ("composition",)
_EMPTY_SEQ_WHEN_ABSENT_TOP = ("advisory_materialisations",)
_NULL_WHEN_ABSENT_IN_COMPOSITION = (
    "predecessor_micro_contract_id",
    "successor_micro_contract_id",
)


def sealed_plan_body(plan: Mapping[str, Any], *, warn: list[str] | None = None) -> dict:
    """CF-SEAL-001 + §6.3. The value hashed and signed for a sealed plan.

    CF-SEAL-002: the signature covers exactly these same bytes. There are not
    two serialisations.

    **RULED by `ERR-P3-003`:** `None` is **PRESENT** and emits as
    `null`, **except where a prune rule names that key**, in which case it is
    ABSENT and omitted entirely. *"Absence is produced only by an explicit prune
    rule; it is never inferred from a value"* — **pruning is a property of the
    FIELD, not of the VALUE.**

    This REVERSES the choice made at T-1 for the four prune-named fields, where
    a present `null` was emitted rather than omitted. Implemented as ruled; the
    T-1 reading is recorded in the log as superseded, not quietly dropped.
    """
    body = {k: v for k, v in plan.items() if k not in _SEAL_PRODUCED_FIELDS}

    # Prune rules name these keys: absent OR null -> omitted.
    for field in _OMIT_WHEN_ABSENT_TOP:
        if field in body and body[field] is None:
            del body[field]
            if warn is not None:
                warn.append(f"A-11 {field}: present-and-null, PRUNED (a prune rule names the key)")

    # No prune rule names these: absent -> the stated default; present null
    # stays null, which is what the default already is for `composition`.
    for field in _NULL_WHEN_ABSENT_TOP:
        body.setdefault(field, None)
    for field in _EMPTY_SEQ_WHEN_ABSENT_TOP:
        body.setdefault(field, [])

    composition = body.get("composition")
    if isinstance(composition, Mapping):
        composition = dict(composition)
        for field in _NULL_WHEN_ABSENT_IN_COMPOSITION:
            composition.setdefault(field, None)
        body["composition"] = composition

    # CF-SEAL-003: `parameter_bindings` is examined ONE LEVEL DEEP, within
    # `transforms` entries only, and a prune rule names it.
    transforms = body.get("transforms")
    if isinstance(transforms, Sequence) and not isinstance(transforms, (str, bytes)):
        rebuilt = []
        for i, entry in enumerate(transforms):
            if isinstance(entry, Mapping) and entry.get("parameter_bindings", ...) is None:
                entry = {k: v for k, v in entry.items() if k != "parameter_bindings"}
                if warn is not None:
                    warn.append(f"A-11 transforms[{i}].parameter_bindings: present-and-null, PRUNED")
            rebuilt.append(entry)
        body["transforms"] = rebuilt
    return body


def intent_body(intent: Mapping[str, Any]) -> dict:
    """CF-INTENT-001. Exactly {intent_kind, intent_version, intent_payload},
    plus `bcl_version` ONLY when present. The intent's own content hash is
    excluded.

    A-12 (open): §6.4 handles `bcl_version` by *inclusion when present*, while
    §6.3 handles the same field by *omission when absent*. The spec states the
    two produce identical bytes and that nothing mechanically guarantees they
    keep agreeing (§11.3). Both are implemented here from their own words, and
    `assert_bcl_version_agreement` below is the mechanical check §11.3 says does
    not exist.
    """
    body = {
        "intent_kind": intent["intent_kind"],
        "intent_version": intent["intent_version"],
        "intent_payload": intent["intent_payload"],
    }
    # A-11 as ruled: a prune rule names `bcl_version`, so absent OR null -> omitted.
    if intent.get("bcl_version") is not None:
        body["bcl_version"] = intent["bcl_version"]
    return body


def request_body(request: Mapping[str, Any]) -> dict:
    """CF-REQUEST-001. The submission timestamp and the request identifier are
    excluded, so the same logical request submitted twice hashes identically."""
    return {
        "submitter": request["submitter"],
        "intent_kind": request["intent_kind"],
        "intent_version": request["intent_version"],
        "intent_payload": request["intent_payload"],
        "intent_content_hash": request["intent_content_hash"],
        "data_bindings": request["data_bindings"],
        "config": request["config"],
    }


def assert_bcl_version_agreement(intent: Mapping[str, Any]) -> bool:
    """§11.3 — the two independently written rules for `bcl_version` must agree
    for ever, and nothing enforces it. This enforces it."""
    by_inclusion = intent_body(intent)
    by_omission = {
        k: v for k, v in {
            "intent_kind": intent["intent_kind"],
            "intent_version": intent["intent_version"],
            "intent_payload": intent["intent_payload"],
            "bcl_version": intent.get("bcl_version"),
        }.items()
        if not (k == "bcl_version" and intent.get("bcl_version") is None)
    }
    return canonical_bytes(by_inclusion) == canonical_bytes(by_omission)


# --- §7 Identifier derivation -------------------------------------------
NAMESPACES = {                                        # CF-ID-002: fixed for v1
    "intent": _uuid.UUID("7d8f4e50-6192-53a4-bd2c-7d8f4e506192"),
    "micro-contract": _uuid.UUID("5b6d2c3e-4f70-5182-9b0a-5b6d2c3e4f70"),
    "composition": _uuid.UUID("8e905f61-72a3-54b5-ce3d-8e905f6172a3"),
    "envelope": _uuid.UUID("6c7e3d4f-5081-5293-ac1b-6c7e3d4f5081"),
    "request-internal": _uuid.UUID("4a5c1b2d-3e6f-5071-8a9b-4a5c1b2d3e6f"),
}


class IdentifierKind(_enum.StrEnum):
    """⚠ **THE CLOSED SET `_derive` ACCEPTS** (`TYPE-001`).

    `_derive` SUBSCRIPTS `NAMESPACES` and tests membership nowhere: as measured,
    it is the **one site of seventeen** where a governed vocabulary
    reaches a parameter that assumes membership rather than checking it. The
    other sixteen are validation boundaries whose whole job is to refuse a
    non-member, and a type forbidding what they exist to refuse would delete
    their refusal path. Here a non-member is a bare `KeyError` from inside the
    callee, naming nothing — so the declared type is the only guard there is,
    and `str` was not it.

    ⚠ **WRITTEN IN CLASS SYNTAX, WHICH IS A DUPLICATION, AND GUARDED BECAUSE OF
    IT.** `enum.StrEnum("IdentifierKind", NAMESPACES)` would derive the members
    from the vocabulary with no second copy — and a type checker cannot see the
    members of a functionally-created enum, so it would enforce nothing. **A
    closed type nothing checks is a decoration.** So the members are written
    out and held to the vocabulary by the assertion below: this is a MIRROR
    WITH A GUARD, not a copy, and the day they diverge the module refuses to
    import (the shape `der.py` already uses for `BOUND_FIELD`).
    """

    INTENT = "intent"
    MICRO_CONTRACT = "micro-contract"
    COMPOSITION = "composition"
    ENVELOPE = "envelope"
    REQUEST_INTERNAL = "request-internal"


if {m.value for m in IdentifierKind} != set(NAMESPACES):    # pragma: no cover
    raise RuntimeError(
        "IdentifierKind and NAMESPACES have diverged: "
        f"{sorted({m.value for m in IdentifierKind} ^ set(NAMESPACES))}. The enum "
        "is a mirror of the vocabulary and a mirror that stops matching is worse "
        "than no mirror — it type-checks callers against a set the code does not use")


def _derive(kind: IdentifierKind, body: Mapping[str, Any]) -> str:
    """CF-ID-001. UUID version 5 over the namespace and, as the name, the
    canonical byte string decoded as UTF-8.

    ⚠ CF-ID-005: UUIDv5 is SHA-1 based. Content integrity does not depend on
    this, but identifier and ordering identity do. New structures MUST NOT key
    on these identifiers.
    """
    name = canonicalise(body)          # already the character sequence; UTF-8 round-trips
    return str(_uuid.uuid5(NAMESPACES[kind], name))


def derive_intent_id(intent_kind, intent_version, intent_payload) -> str:
    return _derive(IdentifierKind.INTENT, {
        "intent_kind": intent_kind,
        "intent_version": intent_version,
        "intent_payload": intent_payload,
    })


def derive_micro_contract_id(compiler_version, substrate_version, intent_content_hash,
                             input_hashes, pinned_contracts, pinned_agents) -> str:
    return _derive(IdentifierKind.MICRO_CONTRACT, {
        "compiler_version": compiler_version,
        "substrate_version": substrate_version,
        "intent_content_hash": intent_content_hash,
        "input_hashes": input_hashes,
        "pinned_contracts": pinned_contracts,
        "pinned_agents": pinned_agents,
    })


def derive_composition_id(compiler_version, substrate_version, intent_content_hash,
                          pinned_contracts, pinned_agents) -> str:
    """"as micro-contract, without `input_hashes`"."""
    return _derive(IdentifierKind.COMPOSITION, {
        "compiler_version": compiler_version,
        "substrate_version": substrate_version,
        "intent_content_hash": intent_content_hash,
        "pinned_contracts": pinned_contracts,
        "pinned_agents": pinned_agents,
    })


def derive_envelope_id(envelope_kind, request_id, position, prior_envelope, payload_hash) -> str:
    """CF-ID-004: an absent `prior_envelope` is encoded as the EMPTY STRING,
    not null.

    A-18: this `prior_envelope` (an identifier, §7) is a different field from
    CEF's `prev_envelope_hash` (a SHA-256 digest, CEF-004). They share the empty
    string as their absence sentinel and differ by one word in their names.
    """
    return _derive(IdentifierKind.ENVELOPE, {
        "envelope_kind": envelope_kind,
        "request_id": request_id,
        "position": position,
        "prior_envelope": "" if prior_envelope is None else prior_envelope,
        "payload_hash": payload_hash,
    })


def derive_request_internal_id(request_id) -> str:
    return _derive(IdentifierKind.REQUEST_INTERNAL, {"request_id": request_id})


# --- §9 ------------------------------------------------------------------
def legacy_chain_head(envelope_identifiers: Sequence[str]) -> str:
    """CF-HEAD-001 (normative, LEGACY). The chain head is the content hash of
    the SEQUENCE OF ENVELOPE IDENTIFIER STRINGS. Verifying a head therefore
    requires the complete ordered list of identifiers.

    Documented by the spec as the construction in use, NOT a recommended one:
    it is linear, and it commits to SHA-1-derived identifiers (CF-ID-005).
    """
    return content_hash(list(envelope_identifiers))


# §9 — fields that reach no canonical byte by any path, and therefore have no
# cryptographic protection whatsoever. An implementation MUST NOT present these
# as verified.
# ⚠ The plan seal is stored beside the
# envelope's own signature and outside `payload_canonical_bytes`, so it is
# unbound here too — see `envelope_form.UNBOUND_FIELDS` for the reason this
# had to be written by hand.
UNBOUND_ENVELOPE_FIELDS = ("stored timestamp", "ordinal", "submitter attribution",
                           "the plan seal's signature and era")
