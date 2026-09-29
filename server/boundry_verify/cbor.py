"""Deterministic CBOR — RFC 8949, core deterministic encoding (section 4.2.1).

 STOP-A. **Standard library only**, guardrail 2 requires:
the verifier must run where nothing can be installed. Written from RFC 8949
alone; the RFC is a permitted input exactly as RFC 8032 and RFC 6962 were.

## Why both a strict decoder AND a re-encode comparison

 requires that what is parsed be re-encoded and compared
byte for byte. That check alone is not enough, and the strict decoder alone is
not enough either:

  * **Re-encoding alone** can silently repair. A lenient decoder that accepts a
    non-shortest length and then emits the shortest one produces bytes that
    differ from the input, so the comparison catches it — but only if the
    decoder did not also normalise something the encoder cannot express.
  * **Strict decoding alone** relies on my enumeration of every rule being
    complete, which is exactly the assumption this programme keeps punishing.

**Two independent instruments agreeing is the claim; either alone is a
single reading.** (`ATTRIBUTION-NEEDS-TWO-READINGS`, applied to a codec.)

## What is deliberately refused

**Floats, in every width.** `CF-TYPE-001`
refuses them from the canonical form, and a bundle codec that accepts a value
the canonical form cannot express would let a record exist that can never be
re-canonicalised. **Marked as this implementation's decision, not the RFC's** —
RFC 8949 permits floats and section 4.2.2 gives their deterministic rules.

**Indefinite lengths, non-shortest arguments, reserved additional information,
`undefined`, duplicate map keys, out-of-order map keys.** All are either
forbidden by section 4.2.1 or unrepresentable under it.

## ⚠: the narrowing is a PROFILE, and it was only half here

`BV-005` gives a seven-row table and this module implemented four rows of it.
**Floats, indefinite lengths, duplicate keys and key order were enforced; TEXT
KEYS ONLY, NFC-NORMALISED TEXT and NO TAGS EXCEPT 2 AND 3 were not** — the last
two arriving with `BV-026`, after this file was written.

**They could not simply be added, because this decoder is also the COSE
decoder.** RFC 9052 header maps are keyed by INTEGERS and a `COSE_Sign1` is
**tag 18**, so a decoder that enforced `BV-005`'s table globally would refuse
every COSE object the bundle carries. *The narrowing belongs to the bundle's
encoding profile, not to the codec.*

**So the profile is a parameter.** `BUNDLE` is `bundle-cbor-det-cf1` — the full
`BV-005` table. `PERMISSIVE` is RFC 8949 section 4.2.1 without the three rows
that are Boundry's rather than the RFC's, and is what the COSE and DER paths
read under. *A profile passed at the call site can be seen; a profile assumed by
a codec cannot.*
"""

from __future__ import annotations

import math
import struct
import unicodedata
from dataclasses import dataclass

__all__ = ["CborError", "Tag", "Profile", "BUNDLE", "PERMISSIVE",
           "HEAD_INT_MAX", "decode", "encode", "assert_round_trip", "REFUSALS"]

#: Named refusal codes. A refusal that says only "bad CBOR" discards the
#: distinction between a hostile encoding and an unsupported one.
REFUSALS = (
    "cbor-truncated",
    "cbor-trailing-bytes",
    "cbor-indefinite-length",
    "cbor-non-shortest-argument",
    "cbor-reserved-additional-information",
    "cbor-float-refused",
    "cbor-undefined-refused",
    "cbor-simple-non-shortest",
    "cbor-invalid-utf8",
    "cbor-duplicate-map-key",
    "cbor-map-keys-unsorted",
    "cbor-unencodable-type",
    "cbor-round-trip-differs",
    # --- BV-005's remaining three rows, ---------------
    "cbor-map-key-not-text",
    "cbor-text-not-nfc",
    "cbor-tag-not-permitted",
    "cbor-bignum-not-minimal",
    "cbor-bignum-malformed",
)


class CborError(Exception):
    """A refusal with a named code. `code` is one of `REFUSALS`.

    `tag_number` is set only by `cbor-tag-not-permitted`. It exists because
    `BV-001`'s refusal — *the outermost item is a `COSE_Sign1`, and a bundle is
    a container and an UNSIGNED one* — is more specific than *"this profile
    permits no tags"*, and the specific refusal must survive the general one
    being added underneath it.
    """

    def __init__(self, code: str, detail: str = "", offset: int | None = None,
                 *, tag_number: int | None = None) -> None:
        self.code = code
        self.detail = detail
        self.offset = offset
        self.tag_number = tag_number
        where = f" at byte {offset}" if offset is not None else ""
        super().__init__(f"{code}{where}: {detail}" if detail else f"{code}{where}")


@dataclass(frozen=True)
class Tag:
    """A CBOR tag. COSE_Sign1 is tag 18, so tags are load-bearing here."""
    number: int
    value: object


#: The largest argument a CBOR head can carry, and therefore the boundary
#: `BV-026`'s `K-2` draws: *"a value that fits a head integer MUST NOT be
#: emitted as a bignum."*
HEAD_INT_MAX = 0xFFFFFFFFFFFFFFFF


@dataclass(frozen=True)
class Profile:
    """Which of `BV-005`'s rows are in force for one decode.

    **The four rows that are RFC 8949 section 4.2.1's own** — no indefinite
    lengths, no duplicate keys, sorted keys, shortest arguments — are
    unconditional and are not fields here, and so is the float exclusion this
    module applies everywhere. **The three rows that are Boundry's** are fields,
    because the COSE and DER objects a bundle carries are not encoded under
    Boundry's narrowing and must not be read as though they were.
    """

    #: The identifier this profile answers to, for a refusal's detail text.
    name: str
    #: `BV-005`: map keys are text strings only.
    text_keys_only: bool
    #: `BV-026` `K-1`: text IS NFC-normalised at the CBOR layer.
    require_nfc_text: bool
    #: `BV-005`/`BV-026` `K-2`: tags none, except 2 and 3 for bignums.
    #: `None` means the profile places no restriction on tag numbers.
    permitted_tags: frozenset | None
    #: Whether tags 2 and 3 are DECODED as integers rather than carried as
    #: `Tag` objects. Only a profile that permits them can interpret them.
    decode_bignums: bool


#: `bundle-cbor-det-cf1` — `BV-005`'s table in full.
BUNDLE = Profile(name="bundle-cbor-det-cf1", text_keys_only=True,
                 require_nfc_text=True, permitted_tags=frozenset({2, 3}),
                 decode_bignums=True)

#: RFC 8949 section 4.2.1 plus the float exclusion, and nothing else. **What the
#: COSE and DER paths read under**, because a `COSE_Sign1` is tag 18 with an
#: integer-keyed header map and is not a Boundry canonical-form object.
#:
#: ⚠ **This is a DEFAULT and it is not `BV-004`'s kind of default.** `BV-004`
#: forbids a verifier inventing an ENCODING IDENTIFIER and then recognising it.
#: This is an internal codec setting chosen at each call site, and the bundle
#: path names `BUNDLE` explicitly rather than inheriting anything.
PERMISSIVE = Profile(name="rfc8949-4.2.1", text_keys_only=False,
                     require_nfc_text=False, permitted_tags=None,
                     decode_bignums=False)


# --- decoding ---------------------------------------------------------------

def _need(data: bytes, offset: int, count: int) -> None:
    if offset + count > len(data):
        raise CborError("cbor-truncated",
                        f"needed {count} byte(s), {len(data) - offset} remain", offset)


def _argument(data: bytes, offset: int) -> tuple[int, int]:
    """Return (value, next_offset) for the head at `offset`, enforcing shortest form."""
    initial = data[offset]
    ai = initial & 0x1F
    if ai < 24:
        return ai, offset + 1
    if ai == 24:
        _need(data, offset + 1, 1)
        value = data[offset + 1]
        if value < 24:
            raise CborError("cbor-non-shortest-argument",
                            f"{value} fits in the initial byte", offset)
        return value, offset + 2
    if ai == 25:
        _need(data, offset + 1, 2)
        value = struct.unpack_from(">H", data, offset + 1)[0]
        if value <= 0xFF:
            raise CborError("cbor-non-shortest-argument",
                            f"{value} fits in one byte", offset)
        return value, offset + 3
    if ai == 26:
        _need(data, offset + 1, 4)
        value = struct.unpack_from(">I", data, offset + 1)[0]
        if value <= 0xFFFF:
            raise CborError("cbor-non-shortest-argument",
                            f"{value} fits in two bytes", offset)
        return value, offset + 5
    if ai == 27:
        _need(data, offset + 1, 8)
        value = struct.unpack_from(">Q", data, offset + 1)[0]
        if value <= 0xFFFFFFFF:
            raise CborError("cbor-non-shortest-argument",
                            f"{value} fits in four bytes", offset)
        return value, offset + 9
    if ai == 31:
        raise CborError("cbor-indefinite-length",
                        "indefinite lengths are not part of core deterministic encoding",
                        offset)
    raise CborError("cbor-reserved-additional-information",
                    f"additional information {ai} is reserved", offset)


def _decode_bignum(number: int, inner: object, start: int) -> int:
    """`BV-026` `K-2`. Tags 2 and 3, RFC 8949 section 3.4.3, MINIMALLY encoded.

    **`K-2` admits these two tags and requires minimal encoding in one breath:**
    *"a value that fits a head integer MUST NOT be emitted as a bignum."* A
    profile that accepted a non-minimal bignum would hold two encodings for one
    integer, which is `BV-006`'s defect inside a number.

    Leading zero bytes are refused for the same reason, and an empty byte string
    is refused because it encodes nothing.
    """
    if not isinstance(inner, bytes):
        raise CborError("cbor-bignum-malformed",
                        f"tag {number} wraps {type(inner).__name__}, not a byte "
                        "string (RFC 8949 section 3.4.3)", start)
    if not inner:
        raise CborError("cbor-bignum-malformed",
                        f"tag {number} wraps an empty byte string", start)
    if inner[0] == 0:
        raise CborError("cbor-bignum-not-minimal",
                        f"tag {number}'s byte string has a leading zero byte", start)
    n = int.from_bytes(inner, "big")
    if n <= HEAD_INT_MAX:
        value = n if number == 2 else -1 - n
        raise CborError(
            "cbor-bignum-not-minimal",
            f"{value} fits a head integer and must not be emitted as a bignum",
            start)
    return n if number == 2 else -1 - n


def _decode_at(data: bytes, offset: int, profile: "Profile") -> tuple[object, int]:
    _need(data, offset, 1)
    initial = data[offset]
    major = initial >> 5
    start = offset

    if major == 7:
        return _decode_simple(data, offset)

    argument, offset = _argument(data, offset)

    if major == 0:
        return argument, offset
    if major == 1:
        return -1 - argument, offset
    if major == 2:
        _need(data, offset, argument)
        return data[offset:offset + argument], offset + argument
    if major == 3:
        _need(data, offset, argument)
        raw = data[offset:offset + argument]
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CborError("cbor-invalid-utf8", str(exc), offset) from None
        if profile.require_nfc_text and unicodedata.normalize("NFC", text) != text:
            # BV-026 K-1: text IS NFC-normalised at the CBOR layer. The
            # narrowing table listed exclusions and not inclusions, "and that is
            # why it read as silent".
            #
            # ⚠ REFUSED rather than normalised, and the difference is the whole
            # point of `assert_round_trip`: normalising here would emit bytes
            # that differ from the input, so the round-trip comparison would
            # report `cbor-round-trip-differs` and say nothing about WHY. A
            # decoder that repairs is a decoder that has accepted a second
            # format and then hidden it.
            #
            # BV-026's own consequence — two keys differing only in composition
            # collapsing onto one encoding and being refused as duplicates —
            # arrives here one step earlier, on the decomposed member itself,
            # under a code that names the cause. Both refuse the same bytes.
            raise CborError(
                "cbor-text-not-nfc",
                "this text string is not NFC-normalised; the profile is narrowed "
                "by the canonical form, which normalises to NFC", start)
        return text, offset + argument
    if major == 4:
        items = []
        for _ in range(argument):
            item, offset = _decode_at(data, offset, profile)
            items.append(item)
        return items, offset
    if major == 5:
        return _decode_map(data, offset, argument, profile)
    # major == 6
    if profile.permitted_tags is not None and argument not in profile.permitted_tags:
        raise CborError(
            "cbor-tag-not-permitted",
            f"tag {argument} is not permitted under {profile.name}; no tags are "
            "admitted except 2 and 3 for bignums",
            start, tag_number=argument)
    inner, offset = _decode_at(data, offset, profile)
    if profile.decode_bignums and argument in (2, 3):
        return _decode_bignum(argument, inner, start), offset
    return Tag(argument, inner), offset


def _keys_in_order(previous: bytes | None, key_bytes: bytes) -> bool:
    """Section 4.2.1's map ordering, as an isolable predicate.

    A module-level function rather than an inline comparison so a test can
    disable this one check and demonstrate that the round-trip comparison
    catches what it was catching (`ISOLABLE-CHECK RULE`). Two instruments that
    cannot be separated cannot be shown to be two.
    """
    return previous is None or key_bytes > previous


def _decode_map(data: bytes, offset: int, count: int,
                profile: "Profile") -> tuple[dict, int]:
    """Decode a map, enforcing section 4.2.1's key ordering and uniqueness.

    **The ordering check runs on the encoded key bytes as they appeared in the
    input**, not on a re-encoding, so a key that is itself non-deterministically
    encoded is caught by `_argument` before the ordering question arises.
    """
    out: dict = {}
    previous: bytes | None = None
    for _ in range(count):
        key_start = offset
        key, offset = _decode_at(data, offset, profile)
        key_bytes = data[key_start:offset]
        if not isinstance(key, (int, str, bytes)):
            raise CborError("cbor-unencodable-type",
                            f"map key of type {type(key).__name__} is not hashable "
                            "in this profile", key_start)
        if profile.text_keys_only and not isinstance(key, str):
            # BV-005's fifth row. It was enforced by `bundle._check_map` on the
            # maps that module walks by name, and NOWHERE ELSE -- so a non-text
            # key inside `record.envelope`, a receipt, or any nested value
            # passed. The rule is a property of the PROFILE, so it belongs at
            # the layer that reads the profile.
            raise CborError("cbor-map-key-not-text",
                            f"map key {key!r} is {type(key).__name__}; "
                            f"{profile.name} carries text-string keys only",
                            key_start)
        if key in out:
            raise CborError("cbor-duplicate-map-key", repr(key), key_start)
        if not _keys_in_order(previous, key_bytes):
            raise CborError(
                "cbor-map-keys-unsorted",
                f"key {key!r} does not follow the previous key in bytewise "
                "lexicographic order of their encodings", key_start)
        previous = key_bytes
        value, offset = _decode_at(data, offset, profile)
        out[key] = value
    return out, offset


def _decode_simple(data: bytes, offset: int) -> tuple[object, int]:
    initial = data[offset]
    ai = initial & 0x1F
    if ai == 20:
        return False, offset + 1
    if ai == 21:
        return True, offset + 1
    if ai == 22:
        return None, offset + 1
    if ai == 23:
        raise CborError("cbor-undefined-refused",
                        "`undefined` has no canonical-form counterpart", offset)
    if ai == 24:
        _need(data, offset + 1, 1)
        value = data[offset + 1]
        if value < 32:
            raise CborError("cbor-simple-non-shortest",
                            f"simple value {value} must use the one-byte form", offset)
        raise CborError("cbor-unencodable-type",
                        f"simple value {value} has no counterpart in this profile", offset)
    if ai in (25, 26, 27):
        raise CborError("cbor-float-refused",
                        "floats are refused: CF-TYPE-001 excludes them from the "
                        "canonical form, so a bundle carrying one holds a value that "
                        "can never be re-canonicalised", offset)
    if ai == 31:
        raise CborError("cbor-indefinite-length", "indefinite-length break", offset)
    raise CborError("cbor-reserved-additional-information",
                    f"additional information {ai} is reserved", offset)


def decode(data: bytes, *, profile: Profile = PERMISSIVE) -> object:
    """Decode one deterministic CBOR item. Trailing bytes are a refusal.

    **Trailing bytes are refused rather than ignored**: a decoder that stops at
    the end of the first item lets a second item ride along unexamined, which is
    the `content-after-the-footer` defect in another format.

    `profile` selects which of `BV-005`'s rows are in force. The bundle path
    passes `BUNDLE`; the COSE and DER paths read RFC 8949 objects that were
    never under Boundry's narrowing and pass nothing.
    """
    value, offset = _decode_at(data, 0, profile)
    if offset != len(data):
        raise CborError("cbor-trailing-bytes",
                        f"{len(data) - offset} byte(s) follow the first item", offset)
    return value


# --- encoding ---------------------------------------------------------------

def _head(major: int, argument: int) -> bytes:
    if argument < 24:
        return bytes([(major << 5) | argument])
    if argument <= 0xFF:
        return bytes([(major << 5) | 24, argument])
    if argument <= 0xFFFF:
        return bytes([(major << 5) | 25]) + struct.pack(">H", argument)
    if argument <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + struct.pack(">I", argument)
    if argument <= 0xFFFFFFFFFFFFFFFF:
        return bytes([(major << 5) | 27]) + struct.pack(">Q", argument)
    raise CborError("cbor-unencodable-type", f"argument {argument} exceeds 64 bits")


def encode(value: object) -> bytes:
    """Encode under core deterministic encoding (section 4.2.1)."""
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, float):
        raise CborError("cbor-float-refused", "floats are refused by this profile")
    if isinstance(value, int):
        # BV-026 K-2, the encoding half. A head integer is emitted as a head
        # integer; only a value that does NOT fit one becomes a bignum, which is
        # exactly the minimality `_decode_bignum` enforces on the way in. The
        # two halves must agree or `assert_round_trip` reports a difference the
        # input never had.
        if 0 <= value <= HEAD_INT_MAX:
            return _head(0, value)
        if -1 - HEAD_INT_MAX <= value < 0:
            return _head(1, -1 - value)
        magnitude = value if value >= 0 else -1 - value
        raw = magnitude.to_bytes((magnitude.bit_length() + 7) // 8, "big")
        return _head(6, 2 if value >= 0 else 3) + _head(2, len(raw)) + raw
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, dict):
        # Section 4.2.1: sorted by the bytewise lexicographic order of the
        # ENCODED keys, which is not the same as sorting the keys themselves.
        encoded = [(encode(key), encode(item)) for key, item in value.items()]
        encoded.sort(key=lambda pair: pair[0])
        return _head(5, len(encoded)) + b"".join(k + v for k, v in encoded)
    if isinstance(value, Tag):
        return _head(6, value.number) + encode(value.value)
    raise CborError("cbor-unencodable-type", type(value).__name__)


def assert_round_trip(data: bytes, *, profile: Profile = PERMISSIVE) -> object:
    """Decode, re-encode, and require byte equality. Returns the decoded value.

*a parser that accepts more than the profile allows
    is a second, undocumented format.* The comparison is what makes that
    statement checkable rather than aspirational.
    """
    value = decode(data, profile=profile)
    again = encode(value)
    if again != data:
        raise CborError(
            "cbor-round-trip-differs",
            f"re-encoding produced {len(again)} byte(s) against {len(data)}; the input "
            "is not core-deterministic even though it parsed")
    return value
