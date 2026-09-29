"""A BOUNDED DER reader — STOP-A.

**Built from X.690 and RFC 5280's DER requirements alone.** The kernel
repository has not been read, and `substrate/witness/` above all.

## Why this module exists before any RFC 3161 code

`ERR-P3-005` carries `witness_token` verbatim and opaque. **A checker for it
must parse attacker-supplied ASN.1 before anything about that token has been
verified** — the signature is what parsing is a prerequisite for, not a
protection available to it. *DER is a notoriously good place to hang a parser,
and this one is written on the assumption that someone will try.*

## ⚠ `BV-023` and `BV-022`, and the precise difference between them here

`BV-023` — **the size of what will be parsed is bounded BEFORE it is parsed**,
from a `Limits` that is a **provisioned input with no default**, and bytes
beyond the bound are **refused unread**.

`BV-022` — **every walk over attacker-supplied structure is bounded**, and an
element longer than its container admits is **refused before it is descended
into**, never discovered by running off the end.

> **⚠ One thing `BV-022` says does NOT transfer to a token, and saying so
> matters.** `BV-022` asks for a bound *read from SIGNED bytes*. **A witness
> token has no signed bytes at parse time** — its signature cannot be checked
> until it has been parsed, so there is nothing signed to take a bound from.
> ***Here the bound is PROVISIONED instead: `Limits` is the operator's decision,
> not the token's account of itself.*** That is `BV-023`'s clause doing
> `BV-022`'s job where `BV-022`'s own source of truth does not yet exist.

## What is refused, and why each is a refusal rather than a tolerance

**DER admits exactly one encoding of each value.** Every tolerance below would
admit a second, and *two encodings of one object is the defect `BV-006` exists
to name* — here it would also mean two byte strings with one signature.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["DerError", "Limits", "Element", "parse", "REFUSALS",
           "PROVISIONED_BOUND_REFUSALS", "BOUND_FIELD",
           "TAG_BOOLEAN", "TAG_INTEGER", "TAG_BIT_STRING", "TAG_OCTET_STRING",
           "TAG_NULL", "TAG_OID", "TAG_UTF8_STRING", "TAG_SEQUENCE", "TAG_SET",
           "TAG_GENERALIZED_TIME", "context"]

REFUSALS = (
    "der-oversize",                 # BV-023: beyond the provisioned byte bound
    "der-truncated",
    "der-indefinite-length",
    "der-non-minimal-length",
    "der-length-overlong",
    "der-length-exceeds-container",  # BV-022: refused before descent
    "der-high-tag-number",
    "der-depth-exceeded",           # BV-022
    "der-element-budget-exceeded",  # BV-022
    "der-trailing-bytes",
    "der-constructed-mismatch",
    "der-non-minimal-integer",
    "der-bad-boolean",
    "der-bad-oid",
    "der-bad-bit-string",
    "der-bad-time",
    "der-unexpected-tag",
    "der-wrong-element-count",
)

#: ⚠ **THE REFUSALS THAT ARE THE OPERATOR'S PROVISIONED BOUND BEING REACHED,
#: RATHER THAN ANYTHING ABOUT THE BYTES.**
#:
#: **Each names one field of `Limits`.** *A token that is merely larger, deeper
#: or busier than a bound WE chose is not a token that is wrong* — the check
#: never ran, and `BV-028` calls that "we are short". **A caller that flattens
#: these into a structural refusal reports the operator's own setting as the
#: record's defect.**
#:
#: ⚠ **`der-length-exceeds-container` is DELIBERATELY NOT HERE.** *It carries a
#: `BV-022` comment like the three below and is a different fact:* a length
#: field that overruns its own container is malformed on its face, whatever
#: bound is in force. **`BV-022` is about refusing before descent; only these
#: three come from `Limits`.**
PROVISIONED_BOUND_REFUSALS = frozenset({
    "der-oversize",                 # max_bytes
    "der-depth-exceeded",           # max_depth
    "der-element-budget-exceeded",  # max_elements
})

#: The `Limits` field each one names, for a refusal that reports the value.
BOUND_FIELD = {
    "der-oversize": "max_bytes",
    "der-depth-exceeded": "max_depth",
    "der-element-budget-exceeded": "max_elements",
}

if not PROVISIONED_BOUND_REFUSALS <= set(REFUSALS):        # pragma: no cover
    raise RuntimeError(
        "PROVISIONED_BOUND_REFUSALS names a code that is not a der refusal: "
        f"{sorted(PROVISIONED_BOUND_REFUSALS - set(REFUSALS))}")
if set(BOUND_FIELD) != PROVISIONED_BOUND_REFUSALS:         # pragma: no cover
    raise RuntimeError("BOUND_FIELD must name exactly the provisioned bounds")

TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_UTF8_STRING = 0x0C
TAG_SEQUENCE = 0x30
TAG_SET = 0x31
TAG_GENERALIZED_TIME = 0x18

#: Universal tags DER requires to be PRIMITIVE. A constructed OCTET STRING is
#: legal BER and is the classic way to smuggle a second encoding past a reader
#: that only checks the tag byte.
_MUST_BE_PRIMITIVE = frozenset({
    TAG_BOOLEAN, TAG_INTEGER, TAG_BIT_STRING, TAG_OCTET_STRING, TAG_NULL,
    TAG_OID, TAG_GENERALIZED_TIME, 0x13, 0x16, 0x17, TAG_UTF8_STRING})

#: Universal tag NUMBERS DER requires to be CONSTRUCTED — the base numbers, not
#: the identifier octets.
#:
#: > **⚠ Repaired STOP-C, where the mutation campaign reported the
#: > guard `INERT`.** It held `TAG_SEQUENCE` and `TAG_SET` — the full identifier
#: > octets `0x30` and `0x31` — and was compared against `tag`. **Both of those
#: > already carry the constructed bit, so `not constructed` could never be true
#: > for a member of the set: the branch was UNREACHABLE.** A SEQUENCE tag with
#: > the constructed bit cleared (`0x10`) parsed with no refusal at all.
#: >
#: > ***And the STOP-A sweep did not catch it, because `der-constructed-mismatch`
#: > was reachable through the OTHER branch.*** **A sweep proving every refusal
#: > CODE reachable does not prove every BRANCH that raises one** — a dead branch
#: > hides inside a live code. *That is a limit of the standard, not a lapse in
#: > applying it, and it is why `RP03` exists beside `RP02`.*
_MUST_BE_CONSTRUCTED = frozenset({TAG_SEQUENCE & 0x1F, TAG_SET & 0x1F})

#: The longest definite-length long form this reader will read. Four octets
#: expresses ~4 GiB, which is already far past any bound an operator would set;
#: refusing more is refusing to do arithmetic on an attacker's behalf.
_MAX_LENGTH_OCTETS = 4


def context(number: int, *, constructed: bool = True) -> int:
    """The identifier octet for a context-specific tag, e.g. `[0]`."""
    return 0x80 | (0x20 if constructed else 0x00) | number


class DerError(Exception):
    """A refusal with a named code. `code` is one of `REFUSALS`."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class Limits:
    """`BV-023`. **Provisioned, with no default on any field.**

    Constructing this requires all three to be stated, so a caller cannot
    acquire a bound by forgetting to choose one. *A default maximum size is an
    operator decision made by whoever wrote the parser.*
    """

    max_bytes: int
    max_depth: int
    max_elements: int

    def __post_init__(self) -> None:
        for name in ("max_bytes", "max_depth", "max_elements"):
            value = getattr(self, name)
            if not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive int, got {value!r}")


@dataclass
class Element:
    """One TLV. `children` is populated for constructed elements only."""

    tag: int
    content: bytes
    children: list = field(default_factory=list)
    #: The element's own complete encoding, kept because CMS signs the DER of
    #: substructures and re-encoding them here would make a signature depend on
    #: THIS module's encoder rather than on the signer's bytes (ERR-P3-005's
    #: reasoning, one layer down).
    raw: bytes = b""

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)


class _Budget:
    """The element allowance for one parse. `BV-022`, counted across the WHOLE
    tree rather than per level — a bound per level bounds nothing, because the
    attacker chooses the breadth."""

    def __init__(self, allowed: int) -> None:
        self.remaining = allowed

    def spend(self) -> None:
        if self.remaining <= 0:
            raise DerError("der-element-budget-exceeded",
                           "the token declares more ASN.1 elements than this "
                           "verifier was provisioned to read; refusing rather "
                           "than continuing to allocate")
        self.remaining -= 1


def _read_length(data: bytes, offset: int, end: int) -> tuple[int, int]:
    """Return `(length, new_offset)`. Definite, minimal, and bounded."""
    if offset >= end:
        raise DerError("der-truncated", "no length octet")
    first = data[offset]
    offset += 1
    if first == 0x80:
        raise DerError("der-indefinite-length",
                       "DER admits definite lengths only; an indefinite length "
                       "makes the end of an element a property of its contents")
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count > _MAX_LENGTH_OCTETS:
        raise DerError("der-length-overlong",
                       f"{count} length octets; this reader reads at most "
                       f"{_MAX_LENGTH_OCTETS}")
    if offset + count > end:
        raise DerError("der-truncated", "length octets run past the container")
    raw = data[offset:offset + count]
    offset += count
    if raw[0] == 0x00:
        raise DerError("der-non-minimal-length",
                       "a leading zero in the long-form length is a second "
                       "encoding of the same number")
    value = int.from_bytes(raw, "big")
    if value < 0x80:
        raise DerError("der-non-minimal-length",
                       f"length {value} is expressible in the short form")
    return value, offset


def _read(data: bytes, offset: int, end: int, depth: int, budget: _Budget,
          limits: Limits) -> tuple[Element, int]:
    budget.spend()
    if depth > limits.max_depth:
        raise DerError("der-depth-exceeded",
                       f"nesting deeper than the provisioned {limits.max_depth}; "
                       "refusing before descending rather than recursing")
    if offset >= end:
        raise DerError("der-truncated", "no identifier octet")
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise DerError("der-high-tag-number",
                       "the high-tag-number form is not used anywhere in RFC 3161's "
                       "structures; refusing rather than implementing a path with "
                       "no vector to test it against (UNREACHABLE-IS-UNTESTABLE)")

    length, offset = _read_length(data, offset, end)

    # ⚠ BV-022, at its sharpest: the declared length is compared to what the
    # container admits BEFORE any of the content is touched. A reader that
    # slices first and checks afterwards has already walked it.
    if length > end - offset:
        raise DerError("der-length-exceeds-container",
                       f"an element declares {length} bytes where its container "
                       f"admits {end - offset}; refused before it is read")

    universal = tag & 0xC0 == 0x00
    constructed = bool(tag & 0x20)
    base = tag & 0x1F
    if universal and base in _MUST_BE_PRIMITIVE and constructed:
        raise DerError("der-constructed-mismatch",
                       f"universal tag {base} must be primitive in DER")
    if universal and base in _MUST_BE_CONSTRUCTED and not constructed:
        raise DerError("der-constructed-mismatch",
                       f"universal tag {base} must be constructed; the identifier "
                       "octet carries no constructed bit")

    content = data[offset:offset + length]
    children: list = []
    if constructed:
        inner = offset
        inner_end = offset + length
        while inner < inner_end:
            child, inner = _read(data, inner, inner_end, depth + 1, budget, limits)
            children.append(child)
        if inner != inner_end:
            raise DerError("der-truncated", "a constructed element's children do "
                                            "not fill it exactly")
    offset += length
    element = Element(tag=tag, content=content, children=children)
    return element, offset


def parse(data: bytes, *, limits: Limits) -> Element:
    """Parse ONE complete DER element from `data`. Raises `DerError`.

    `limits` is keyword-only and required: **`BV-023` is not satisfiable by a
    parser that can be called without stating its bounds.**
    """
    if not isinstance(limits, Limits):
        raise TypeError("limits must be a Limits; there is no default")
    # ⚠ BV-023, and the order is the whole of it. The length is taken from the
    # buffer object, not by reading its contents, and nothing below this line
    # runs for an oversize input.
    if len(data) > limits.max_bytes:
        raise DerError("der-oversize",
                       f"{len(data)} bytes offered where this verifier was "
                       f"provisioned for {limits.max_bytes}; refused UNREAD")
    budget = _Budget(limits.max_elements)
    element, offset = _read(data, 0, len(data), 1, budget, limits)
    if offset != len(data):
        raise DerError("der-trailing-bytes",
                       f"{len(data) - offset} byte(s) follow the top-level "
                       "element; a token with a tail has two readings")
    _attach_raw(data, element, 0)
    return element


def _attach_raw(data: bytes, element: Element, start: int) -> int:
    """Record each element's own complete encoding, without re-encoding it."""
    header = 1
    first = data[start + 1]
    header += 1 if first < 0x80 else 1 + (first & 0x7F)
    total = header + len(element.content)
    element.raw = data[start:start + total]
    inner = start + header
    for child in element.children:
        inner = _attach_raw(data, child, inner)
    return start + total


# --------------------------------------------------------------- accessors
def expect(element: Element, tag: int, where: str) -> Element:
    if element.tag != tag:
        raise DerError("der-unexpected-tag",
                       f"{where}: expected tag 0x{tag:02x}, got 0x{element.tag:02x}")
    return element


def fields(element: Element, where: str, *, minimum: int, maximum: int) -> list:
    n = len(element.children)
    if not minimum <= n <= maximum:
        raise DerError("der-wrong-element-count",
                       f"{where}: {n} element(s), expected {minimum}..{maximum}")
    return element.children


def integer(element: Element, where: str) -> int:
    expect(element, TAG_INTEGER, where)
    raw = element.content
    if not raw:
        raise DerError("der-non-minimal-integer", f"{where}: empty INTEGER")
    if len(raw) > 1 and raw[0] == 0x00 and raw[1] < 0x80:
        raise DerError("der-non-minimal-integer",
                       f"{where}: a redundant leading zero octet")
    if len(raw) > 1 and raw[0] == 0xFF and raw[1] >= 0x80:
        raise DerError("der-non-minimal-integer",
                       f"{where}: a redundant leading 0xFF octet")
    return int.from_bytes(raw, "big", signed=True)


def octets(element: Element, where: str) -> bytes:
    expect(element, TAG_OCTET_STRING, where)
    return element.content


def boolean(element: Element, where: str) -> bool:
    expect(element, TAG_BOOLEAN, where)
    if len(element.content) != 1 or element.content[0] not in (0x00, 0xFF):
        raise DerError("der-bad-boolean",
                       f"{where}: DER admits only 0x00 and 0xFF for BOOLEAN")
    return element.content[0] == 0xFF


def bit_string(element: Element, where: str) -> bytes:
    """The BIT STRING's octets, requiring zero unused bits."""
    expect(element, TAG_BIT_STRING, where)
    if not element.content:
        raise DerError("der-bad-bit-string", f"{where}: empty BIT STRING")
    unused = element.content[0]
    if unused != 0:
        raise DerError("der-bad-bit-string",
                       f"{where}: {unused} unused bits; every BIT STRING this "
                       "reader accepts is octet-aligned")
    return element.content[1:]


def oid(element: Element, where: str) -> str:
    """The OID in dotted form. Refuses non-minimal (padded) subidentifiers."""
    expect(element, TAG_OID, where)
    raw = element.content
    if not raw:
        raise DerError("der-bad-oid", f"{where}: empty OBJECT IDENTIFIER")
    if raw[-1] & 0x80:
        raise DerError("der-bad-oid", f"{where}: truncated final subidentifier")
    first = raw[0]
    parts = [str(min(first // 40, 2)), str(first - 40 * min(first // 40, 2))]
    value = 0
    started = False
    for byte in raw[1:]:
        if not started and byte == 0x80:
            raise DerError("der-bad-oid",
                           f"{where}: a padded subidentifier is a second encoding")
        started = bool(byte & 0x80)
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def generalized_time(element: Element, where: str) -> str:
    """The GeneralizedTime, **syntax checked and VALUE NEVER JUDGED**.

    > **⚠ ** *A verifier does not know what time it is in any
    > sense a record can rely on, and a checker that rejects a token for being
    > too old has substituted its own clock for evidence.* **So this returns the
    > time as text and this module never compares it to anything.**
    >
    > Its SYNTAX is checked, because a malformed time is a malformed token and
    > DER admits exactly one spelling: `YYYYMMDDHHMMSS[.f+]Z`, UTC, no offset,
    > no omitted seconds, no trailing zeros in the fraction.
    """
    expect(element, TAG_GENERALIZED_TIME, where)
    try:
        text = element.content.decode("ascii")
    except UnicodeDecodeError:
        raise DerError("der-bad-time", f"{where}: not ASCII") from None
    if not text.endswith("Z"):
        raise DerError("der-bad-time",
                       f"{where}: DER requires the Z form; a local-time or "
                       "offset spelling is a second encoding of one instant")
    body = text[:-1]
    if "." in body:
        body, _, fraction = body.partition(".")
        if not fraction or not fraction.isdigit() or fraction.endswith("0"):
            raise DerError("der-bad-time",
                           f"{where}: DER forbids an empty or zero-padded fraction")
    if len(body) != 14 or not body.isdigit():
        raise DerError("der-bad-time",
                       f"{where}: expected YYYYMMDDHHMMSS, got {body!r}")
    month, day = int(body[4:6]), int(body[6:8])
    hour, minute, second = int(body[8:10]), int(body[10:12]), int(body[12:14])
    if not (1 <= month <= 12 and 1 <= day <= 31 and hour <= 23
            and minute <= 59 and second <= 60):
        raise DerError("der-bad-time", f"{where}: {text!r} is not a calendar time")
    return text
