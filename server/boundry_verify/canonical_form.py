"""The Boundry Canonical Form, version 1 — an independent implementation.

Written (RATIFIED v1.0, 29 Aug 2026) ALONE,
's authorship guardrail. The author of this file has not read the
Boundry kernel, its tests, its corpora or its golden vectors.

Standard library only. No network. Rule identifiers in comments are the
specification's own (`CF-...`) so a failure names the rule it violates.

Every place this file had to guess is recorded in ../AMBIGUITY_LOG.md with the
same tag used at the guess site (A-nn). A guess is never silently resolved.
"""

from __future__ import annotations

import hashlib
import unicodedata
import uuid as _uuid
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any, Mapping, Sequence

__all__ = [
    "MAPPING_KEY_NOT_UNIQUE",
    "CanonicalFormError",
    "canonicalise",
    "canonical_bytes",
    "content_hash",
    "SEAL_PROFILE",
    "FULL_PROFILE",
    "DEFAULT_MAX_DEPTH",
]

# --- refusal classes (§8) ------------------------------------------------
TYPE_UNSUPPORTED = "type-unsupported"            # CF-TYPE-001
DECIMAL_NOT_FINITE = "decimal-not-finite"        # CF-DEC-001
STRING_NOT_ENCODABLE = "string-not-encodable"    # CF-STR-006
MAPPING_KEY_NOT_STRING = "mapping-key-not-string"  # CF-MAP-001
MAPPING_KEY_NOT_UNIQUE = "mapping-key-not-unique"  # CF-MAP-006 (DRAFT, )
DEPTH_EXCEEDED = "depth-exceeded"                # CF-DEPTH-001


class CanonicalFormError(Exception):
    """A value with no canonical form (§8).

    `refusal_class` is the language-neutral class named by the specification;
    conformance is defined on that string, not on this exception type.
    """

    def __init__(self, refusal_class: str, rule: str, detail: str = "") -> None:
        self.refusal_class = refusal_class
        self.rule = rule
        self.detail = detail
        super().__init__(f"{refusal_class} ({rule}){': ' + detail if detail else ''}")


SEAL_PROFILE = "seal"
FULL_PROFILE = "full"

# ⚠ CF-DEPTH-001, PROMOTED.
#
# The clause used to say an implementation SHOULD impose a depth limit and named
# no value, so 64 was this implementation's own choice and explicitly "not a
# conformance claim". That SHOULD contradicted ERR-P4-002's ruled MUST -- a crash
# is not a verdict -- and the contradiction resolved in ERR-P4-002's favour.
#
# 64 IS NOW A CONSTANT OF THE SPECIFICATION, not a per-implementation choice.
# The distinction is not cosmetic: while it was a choice, the kernel canonicaliser
# had no limit at all and emitted where this side refused. A measurement caught that
# split live at depth 65 -- ERR-P4-001 INCOHERENT, reachable from caller content.
#
# DERIVATION (and stated because a constant without one
# is a number somebody liked): both implementations consume 2.0 interpreter
# frames per nesting level; CPython's default recursion limit is 1000; depth 64
# costs 128 frames and leaves 872 -- 87% headroom for the caller's own stack. The
# deepest structure the programme owns is 6, across 143 golden vectors and 21
# canon records, so 64 is 11x real usage.
#
# The kernel spells this constant independently (compiler/determinism/canonical.py
# MAX_DEPTH). Two witnesses, no shared eye; agreement is proven at the vectors.
DEFAULT_MAX_DEPTH = 64


def _nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)


def _emit_string(s: str) -> str:
    """CF-STR-001..006."""
    s = _nfc(s)                                   # CF-STR-001
    try:
        s.encode("utf-8")                         # CF-STR-006 (A-13: checked after NFC)
    except UnicodeEncodeError as exc:
        raise CanonicalFormError(
            STRING_NOT_ENCODABLE, "CF-STR-006", "unpaired surrogate codepoint"
        ) from exc

    out = ['"']
    for ch in s:
        if ch == "\\":
            out.append("\\\\")                    # CF-STR-002
        elif ch == '"':
            out.append('\\"')                     # CF-STR-002
        elif ch == "\b":
            out.append("\\b")                     # CF-STR-003
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))       # CF-STR-004, lowercase hex
        else:
            out.append(ch)                        # CF-STR-005, literal, incl. U+007F
    out.append('"')
    return "".join(out)


def _emit_integer(v: int) -> str:
    """CF-INT-001. Python's int is unbounded and str() emits no leading zeros,
    no '+', no separators and no exponent."""
    return str(v)


def _emit_decimal(v: Decimal) -> str:
    """CF-DEC-001..008, applied to the triple of §2.1."""
    if not v.is_finite():                         # CF-DEC-001
        raise CanonicalFormError(DECIMAL_NOT_FINITE, "CF-DEC-001", str(v))
    sign_flag, digits, exponent = v.as_tuple()
    sign = "-" if sign_flag else ""               # CF-DEC-007: from the triple, not the value
    D = "".join(str(d) for d in digits)
    E = int(exponent)

    if E == 0:                                    # CF-DEC-003
        return sign + (D if D else "0")
    if E > 0:                                     # CF-DEC-004
        return sign + D + ("0" * E)
    if -E >= len(D):                              # CF-DEC-005
        return sign + "0." + ("0" * (-E - len(D))) + D
    split = len(D) + E                            # CF-DEC-006
    left, right = D[:split], D[split:]
    # A-14: `left` cannot be empty in this branch (split > 0), so the spec's
    # "(or 0 if empty)" clause is unreachable. ERRATA_P3_01 accepts this as
    # harmless. Implemented as written anyway.
    return sign + (left if left else "0") + "." + right


def _emit_bytes(v: bytes) -> str:
    """CF-BYTES-001 (full profile). Lowercase hex, two digits per octet."""
    return '"' + v.hex() + '"'


def _emit_uuid(v: _uuid.UUID) -> str:
    """CF-UUID-001 (full profile). The lowercase hyphenated form, as a string."""
    return _emit_string(str(v))


def _emit_timestamp(v: datetime) -> str:
    """CF-TS-001..003 (full profile). Integer microseconds since the epoch,
    by exact integer arithmetic — never via a floating-point seconds value."""
    dt = v if v.tzinfo is not None else v.replace(tzinfo=timezone.utc)  # CF-TS-002
    delta = dt - datetime(1970, 1, 1, tzinfo=timezone.utc)
    micros = (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds
    return _emit_integer(micros)                  # CF-TS-003 handles negatives


def canonicalise(
    value: Any,
    *,
    profile: str = FULL_PROFILE,
    max_depth: int | None = None,
    _depth: int = 0,
) -> str:
    """Return the canonical character sequence for `value` (§3-§5).

    The byte string is its UTF-8 encoding — see `canonical_bytes`.
    """
    # Read the module limit at CALL time. ⚠ Found by mutation M12 at T-3: with
    # `max_depth=DEFAULT_MAX_DEPTH` as a default argument, the constant was bound
    # once at definition and changing it did nothing — a documented knob that
    # silently had no effect. The mutation was INERT for that reason, which is a
    # finding about this file, not about the mutation.
    if max_depth is None:
        max_depth = DEFAULT_MAX_DEPTH
    if _depth > max_depth:                        # CF-DEPTH-001; also catches cycles
        raise CanonicalFormError(DEPTH_EXCEEDED, "CF-DEPTH-001", f"depth > {max_depth}")

    # Dispatch order is normative in effect, not just convenient:
    #   - bool BEFORE int  (the spec's own implementation note; bool is a subclass
    #     of int in Python and reversing this emits `1` where `true` is required)
    #   - datetime BEFORE date (A-16: the identical hazard, in the same language
    #     the spec names, which the spec does NOT warn about — datetime is a
    #     subclass of date, so a date-first test would swallow every timestamp.
    #     ERRATA_P3_01 accepts this. OWNER: Research seat. DATE: the next
    #     revision pack.
    #     [DISCLOSE-001 backfill: recorded as a STOP, because that
    #     pack forbade touching this file; discharged here, which
    #     owns it. Its twin at VERIFIER/AMBIGUITY_LOG.md:149 was discharged at
    #     earlier, and this comment was the duplicate left reading as open.])
    if value is None:
        return "null"                             # CF-NULL-001
    if isinstance(value, bool):
        return "true" if value else "false"       # CF-BOOL-001
    if isinstance(value, int):
        return _emit_integer(value)               # CF-INT-001
    if isinstance(value, str):
        return _emit_string(value)                # §4.4

    if isinstance(value, Mapping):
        return _emit_mapping(value, profile=profile, max_depth=max_depth, _depth=_depth)

    if isinstance(value, (bytes, bytearray)):
        _require_full(profile, "byte string", "CF-BYTES-001")
        return _emit_bytes(bytes(value))
    if isinstance(value, Decimal):
        _require_full(profile, "decimal", "CF-DEC-001")
        return _emit_decimal(value)
    if isinstance(value, _uuid.UUID):
        _require_full(profile, "uuid", "CF-UUID-001")
        return _emit_uuid(value)
    if isinstance(value, datetime):
        _require_full(profile, "timestamp", "CF-TS-001")
        return _emit_timestamp(value)
    if isinstance(value, date):
        # CF-TS-004: a date without a time of day is not a value in this model.
        raise CanonicalFormError(TYPE_UNSUPPORTED, "CF-TS-004", "date without time")

    if isinstance(value, Sequence):
        return _emit_sequence(value, profile=profile, max_depth=max_depth, _depth=_depth)

    # CF-TYPE-001 / §2.2 — floats land here deliberately (§8).
    raise CanonicalFormError(TYPE_UNSUPPORTED, "CF-TYPE-001", type(value).__name__)


def _require_full(profile: str, what: str, rule: str) -> None:
    # A-17: CF-PROFILE-001 states what a seal-profile implementation can
    # reproduce; it does not say a seal-profile implementation must REFUSE the
    # four full-profile types. This implementation refuses them under the seal
    # profile so that the profile boundary is observable rather than silent.
    if profile == SEAL_PROFILE:
        raise CanonicalFormError(
            TYPE_UNSUPPORTED, rule, f"{what} is outside the seal profile (CF-PROFILE-001)"
        )


def _emit_sequence(value: Sequence, *, profile: str, max_depth: int, _depth: int) -> str:
    """CF-SEQ-001/002. There is one sequence type; list and tuple emit identically."""
    parts = [
        canonicalise(v, profile=profile, max_depth=max_depth, _depth=_depth + 1)
        for v in value
    ]
    return "[" + ",".join(parts) + "]"


def _emit_mapping(value: Mapping, *, profile: str, max_depth: int, _depth: int) -> str:
    """CF-MAP-001..005. The order of these steps is normative and observable."""
    pairs: list[tuple[str, str]] = []
    seen_keys: dict[str, str] = {}          # CF-MAP-006
    for key, val in value.items():                # CF-MAP-002, in iteration order
        if isinstance(key, bool) or not isinstance(key, str):
            raise CanonicalFormError(
                MAPPING_KEY_NOT_STRING, "CF-MAP-001", type(key).__name__
            )
        normalised = _nfc(key)
        # ── CF-MAP-006 (DRAFT, ─────────────────────────────────
        # ⚠ REFUSE THE COLLISION. Two keys equal after NFC are THE SAME KEY
        # under the identity model CF-MAP-002 declares -- and emitting both
        # says "these are the same key" and then writes both of them.
        #
        # Until this emitted a duplicate key, which OUR OWN STRICT DECODER
        # REFUSES BY NAME (cbor.py: cbor-duplicate-map-key). The canonicaliser
        # emitted bytes the verifier had to reject: ERR-P4-001 INCOHERENT,
        # reachable from caller-supplied content.
        #
        # REFUSED, NOT REPAIRED (BV-031 limb 1). Dropping one of the pair is a
        # repair that silently loses a value the caller supplied; refusal is
        # the only outcome in which the substrate never lies about its input.
        if normalised in seen_keys:
            raise CanonicalFormError(
                MAPPING_KEY_NOT_UNIQUE, "CF-MAP-006",
                f"{normalised!r} is supplied twice after NFC normalisation "
                f"({seen_keys[normalised]!r} and {key!r}); CF-MAP-002 makes "
                "them one key, so this mapping has no canonical form")
        seen_keys[normalised] = key
        # Value canonicalised here, BEFORE the sort — so a refusal fires in
        # iteration order, which is observable behaviour.
        pairs.append(
            (normalised, canonicalise(val, profile=profile, max_depth=max_depth, _depth=_depth + 1))
        )

    # CF-MAP-003: stable sort by NFC-normalised key, ascending, by Unicode
    # codepoint. list.sort is stable, and str comparison in Python is by
    # codepoint. ⚠ CF-MAP-005 formerly said keys equal after NFC BOTH survive
    # and the output was "deliberately not key-unique". CF-MAP-006
    # refuses that pair above, so the output IS key-unique and the sort can no
    # longer produce a duplicate.
    pairs.sort(key=lambda p: p[0])

    body = ",".join(_emit_string(k) + ":" + v for k, v in pairs)  # CF-MAP-004
    return "{" + body + "}"


def canonical_bytes(value: Any, *, profile: str = FULL_PROFILE,
                    max_depth: int | None = None) -> bytes:
    """CF-ENC-001. The canonical form as a UTF-8 byte string."""
    return canonicalise(value, profile=profile, max_depth=max_depth).encode("utf-8")


def content_hash(value: Any, *, profile: str = FULL_PROFILE,
                 max_depth: int | None = None) -> str:
    """CF-HASH-001. Lowercase hexadecimal SHA-256 of the canonical byte string."""
    return hashlib.sha256(canonical_bytes(value, profile=profile, max_depth=max_depth)).hexdigest()


def has_nfc_key_collision(value: Mapping) -> list[str]:
    """CF-MAP-006 — the normalised keys that more than one supplied key maps onto.

    ⚠ THIS FUNCTION WAS WRITTEN, WAS CORRECT, AND WAS NEVER CALLED. It existed
    from the first version of this module and the emit path never consulted it,
    so the defect it detects shipped for as long as the detector did.

    > *A guard that exists and is not invoked is indistinguishable from a guard
    > that was never written -- except that it reads as protection.*

    `_emit_mapping` now refuses the collision directly (CF-MAP-006). This
    remains as the non-raising query, for a caller that wants to inspect a
    mapping before offering it.
    """
    seen: dict[str, int] = {}
    for key in value.keys():
        if isinstance(key, str):
            n = _nfc(key)
            seen[n] = seen.get(n, 0) + 1
    return sorted(k for k, n in seen.items() if n > 1)
