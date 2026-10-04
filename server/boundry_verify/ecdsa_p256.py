"""`ecdsa_p256` — ECDSA signature VERIFICATION over NIST P-256.

⚠⚠ **Landing B.** Landing A gave the offline verifier RSA;
this gives it the other algorithm a commercial timestamp authority is likely to
sign with. SEC 1 v2.0 §4.1.4 and FIPS 186-4 §6.4.2, implemented from the
specifications.

⚠ **STANDARD LIBRARY ONLY** — guardrail 2, as `ed25519.py` and
`rsa_pkcs1.py` honour it. Integer arithmetic, `hashlib` at the caller, and
Python's own `pow` for the modular inverse. **No `cryptography`, no packages.**

⚠⚠ **THIS IS NOT CONSTANT TIME AND DOES NOT NEED TO BE, AND SAYING SO IS PART OF
THE CONTRACT.** Verification touches only public data — the public key, the
message digest, the signature. There is no secret here to leak by timing.
*Claiming a timing property this code does not have would be worse than making
no claim at all*, and a reader who finds a branch on a signature byte should be
able to tell whether it was considered.

⚠ **THE CURVE PARAMETERS ARE TRANSCRIBED AND ARE NOT TRUSTED.** Three
instruments check them and none trusts the others: the host's `openssl` prints
them, the vector file records that comparison, and `V2_FORM` re-derives the
arithmetic — `G` on the curve, `n·G` the identity, `p` and `n` prime by
Miller-Rabin with stated witnesses. Landing A shipped a one-byte transcription
error in a table nobody could check; that is why.

⚠ **K-3.** Import is definitions only: no I/O, no clock, no network.
"""

from __future__ import annotations

__all__ = ["EcdsaError", "REFUSALS", "CURVE_P256", "verify", "is_on_curve"]

#: Every way this module declines. ⚠ A refusal that cannot be told from another
#: refusal is one finding wearing several names.
REFUSALS: tuple[str, ...] = (
    "ecdsa-r-out-of-range",
    "ecdsa-s-out-of-range",
    "ecdsa-point-not-on-curve",
    "ecdsa-point-at-infinity",
    "ecdsa-digest-length",
)

#: ⚠⚠ **NIST P-256 / secp256r1 / prime256v1** — SEC 2 v2.0 §2.4.2, FIPS 186-4
#: D.1.2.3. Digested over PAIRS by the register, so the VALUES are governed and
#: not merely the names. Checked three ways; see the module docstring.
CURVE_P256: dict[str, int] = {
    "p":  0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    "a":  0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
    "b":  0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    "Gx": 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    "Gy": 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
    "n":  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    "h":  1,
}

_P = CURVE_P256["p"]
_A = CURVE_P256["a"]
_B = CURVE_P256["b"]
_N = CURVE_P256["n"]
_G = (CURVE_P256["Gx"], CURVE_P256["Gy"])

#: The digest this curve is paired with. ⚠ Cited as RFC 5758 §3.2 until a
#: correction: that section covers ECDSA OIDs in certificates and CRLs.
#: The CMS pairing rule is RFC 5753 §2.1.1.
DIGEST_OCTETS = 32


class EcdsaError(Exception):
    """A refusal, carrying its code so a caller can tell which one it is."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def is_on_curve(x: int, y: int) -> bool:
    """`y² ≡ x³ + ax + b (mod p)`. SEC 1 §3.2.2."""
    return (y * y - (x * x * x + _A * x + _B)) % _P == 0


# ── Jacobian coordinates (X, Y, Z) with x = X/Z², y = Y/Z³ ─────────────────
# ⚠ **AFFINE ARITHMETIC WOULD NEED A MODULAR INVERSE PER DOUBLING** — about 256
# of them for one scalar multiplication. Jacobian needs ONE, at the end. The
# identity is any point with Z = 0.

def _jacobian_double(pt):
    X, Y, Z = pt
    if Y == 0 or Z == 0:
        return (0, 0, 0)
    # a = -3 for P-256, which is what makes this the short form
    S = (4 * X * Y * Y) % _P
    M = (3 * X * X + _A * pow(Z, 4, _P)) % _P
    Xr = (M * M - 2 * S) % _P
    Yr = (M * (S - Xr) - 8 * pow(Y, 4, _P)) % _P
    Zr = (2 * Y * Z) % _P
    return (Xr, Yr, Zr)


def _jacobian_add(p1, p2):
    X1, Y1, Z1 = p1
    X2, Y2, Z2 = p2
    if Z1 == 0:
        return p2
    if Z2 == 0:
        return p1
    U1 = (X1 * Z2 * Z2) % _P
    U2 = (X2 * Z1 * Z1) % _P
    S1 = (Y1 * pow(Z2, 3, _P)) % _P
    S2 = (Y2 * pow(Z1, 3, _P)) % _P
    if U1 == U2:
        if S1 != S2:
            return (0, 0, 0)          # P + (-P) = identity
        return _jacobian_double(p1)
    H = (U2 - U1) % _P
    R = (S2 - S1) % _P
    H2 = (H * H) % _P
    H3 = (H * H2) % _P
    Xr = (R * R - H3 - 2 * U1 * H2) % _P
    Yr = (R * (U1 * H2 - Xr) - S1 * H3) % _P
    Zr = (H * Z1 * Z2) % _P
    return (Xr, Yr, Zr)


def _jacobian_mul(k: int, pt):
    """`k·pt`, left-to-right double-and-add. ⚠ Not constant time; see the
    module docstring — every input here is public."""
    result = (0, 0, 0)
    addend = pt
    while k:
        if k & 1:
            result = _jacobian_add(result, addend)
        addend = _jacobian_double(addend)
        k >>= 1
    return result


def _to_affine(pt):
    X, Y, Z = pt
    if Z == 0:
        return None                    # the point at infinity
    zinv = pow(Z, -1, _P)
    return ((X * zinv * zinv) % _P, (Y * pow(zinv, 3, _P)) % _P)


def verify(qx: int, qy: int, message_hash: bytes, r: int, s: int) -> bool:
    """Does `(r, s)` verify over `message_hash` under the public key `(qx, qy)`?

    SEC 1 v2.0 §4.1.4, in the specification's step order. Returns True or False
    for a well-formed input; RAISES :class:`EcdsaError` for an input this module
    declines to attempt.

    ⚠ **THE DISTINCTION IS THE POINT** (`BV-028`): *"this signature does not
    verify"* and *"this pack will not attempt it"* are different facts about
    different parties.

    ⚠ **THE HIGH-S TWIN `(r, n−s)` IS ACCEPTED, DELIBERATELY.** ECDSA is
    malleable by construction and SEC 1 §4.1.4 admits both; refusing the twin
    would refuse conforming tokens a real authority may emit. Low-S policies
    exist where a signature is used as an identifier — this verifier uses the
    seal's own digest for that. The vectors carry the twin with the oracle's
    verdict beside this pack's, so the policy is visible rather than implied.
    """
    if len(message_hash) != DIGEST_OCTETS:
        raise EcdsaError("ecdsa-digest-length",
                         f"the digest is {len(message_hash)} octet(s); this "
                         f"curve pairs with SHA-256 ({DIGEST_OCTETS}), "
                         "RFC 5753 §2.1.1")
    # ── step 1: r and s in [1, n-1] ───────────────────────────────────────
    if not 1 <= r <= _N - 1:
        raise EcdsaError("ecdsa-r-out-of-range",
                         f"r is not in [1, n-1]; SEC 1 §4.1.4 step 1")
    if not 1 <= s <= _N - 1:
        raise EcdsaError("ecdsa-s-out-of-range",
                         f"s is not in [1, n-1]; SEC 1 §4.1.4 step 1")
    # ── the public key must be a point on the curve, and not the identity ─
    if qx == 0 and qy == 0:
        raise EcdsaError("ecdsa-point-at-infinity",
                         "the public key is the identity; SEC 1 §3.2.2.1")
    if not is_on_curve(qx, qy):
        raise EcdsaError("ecdsa-point-not-on-curve",
                         "the public key does not satisfy the curve equation; "
                         "SEC 1 §3.2.2.1")

    # ── step 2: e from the digest ─────────────────────────────────────────
    # ⚠ SEC 1 §4.1.3 step 3 takes the leftmost min(bitlen(n), bitlen(hash))
    # bits. P-256's n is 256 bits and SHA-256 is 256 bits, so the truncation
    # is the IDENTITY here. It is written down rather than omitted: a reader
    # who assumes it was forgotten cannot tell that from one who assumes it
    # was considered.
    e = int.from_bytes(message_hash, "big")

    # ── steps 3-5 ─────────────────────────────────────────────────────────
    w = pow(s, -1, _N)
    u1 = (e * w) % _N
    u2 = (r * w) % _N
    point = _jacobian_add(_jacobian_mul(u1, (_G[0], _G[1], 1)),
                          _jacobian_mul(u2, (qx, qy, 1)))
    affine = _to_affine(point)
    if affine is None:
        # ⚠ R = infinity is a REFUSAL of the signature, not of the input: the
        # specification says reject, and returning False says exactly that.
        return False
    return affine[0] % _N == r
