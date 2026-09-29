"""Ed25519 verification, implemented from RFC 8032 §5.1 alone.

Guardrail 2: standard library ONLY. No `cryptography`, no packages.
This is a claimed property of the invention, not a preference — the verifier
must run where nothing can be installed.

Scope: §5.1.7 (Verify) and the primitives it needs — §5.1.2 encoding,
§5.1.3 decoding, §5.1.4 point arithmetic. **Signing is deliberately absent
from the verifier.** The test-only signer used to build synthetic material
lives in `testing/synthetic.py` and is not importable from here.

⚠: this is straightforward modular arithmetic on Python ints and
is NOT constant-time. For a verifier that is acceptable — it handles only public
values (public key, signature, message) and holds no secret — but it must never
be reused for signing, and that is why no signing primitive is defined here.
"""

from __future__ import annotations

import hashlib

__all__ = ["verify", "SIGNATURE_SIZE", "PUBLIC_KEY_SIZE", "Ed25519Error"]

SIGNATURE_SIZE = 64
PUBLIC_KEY_SIZE = 32

# RFC 8032 §5.1 parameters
_p = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _p - 2, _p) % _p
_SQRT_M1 = pow(2, (_p - 1) // 4, _p)


class Ed25519Error(Exception):
    """Raised for malformed inputs. A bad signature is `False`, not an error —
    only structurally impossible input raises."""


def _inv(x: int) -> int:
    return pow(x, _p - 2, _p)


# --- §5.1.4 point arithmetic, extended coordinates (X, Y, Z, T) ----------
def _point_add(P, Q):
    """add-2008-hwcd-3, unified for a = -1 (so it also doubles correctly)."""
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % _p
    B = (Y1 + X1) * (Y2 + X2) % _p
    C = 2 * T1 * T2 * _d % _p
    D = 2 * Z1 * Z2 % _p
    E = (B - A) % _p
    F = (D - C) % _p
    G = (D + C) % _p
    H = (B + A) % _p
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _scalar_mult(P, e: int):
    Q = (0, 1, 1, 0)          # the neutral element
    while e > 0:
        if e & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        e >>= 1
    return Q


def _point_equal(P, Q) -> bool:
    X1, Y1, Z1, _ = P
    X2, Y2, Z2, _ = Q
    return (X1 * Z2 - X2 * Z1) % _p == 0 and (Y1 * Z2 - Y2 * Z1) % _p == 0


def _recover_x(y: int, sign: int):
    """§5.1.3. Returns None where the RFC says to reject."""
    if y >= _p:
        return None
    x2 = (y * y - 1) * _inv(_d * y * y + 1) % _p
    if x2 == 0:
        # The RFC: if x is zero and the sign bit is set, decoding fails.
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * _SQRT_M1 % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x % 2) != sign:
        x = _p - x
    return x


def _decompress(s: bytes):
    """§5.1.3 point decoding. Returns None on any rejection condition."""
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _p)


# The base point B: y = 4/5, x the even root. §5.1.
_By = 4 * _inv(5) % _p
_Bx = _recover_x(_By, 0)
_B = (_Bx, _By, 1, _Bx * _By % _p)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 §5.1.7. Returns True only if the signature is valid.

    The RFC's three rejection conditions are all enforced:
      1. R or A does not decode to a curve point  -> reject
      2. S is not in the range [0, L)             -> reject  (malleability)
      3. [S]B != R + [k]A                         -> reject

     RULED by `ERR-P3-006`: the required variant is **RFC 8032
    §5.1.7 verification, cofactorless equation, with no additional canonicality
    checks beyond those §5.1.7 states**, and a cofactored variant MUST NOT be
    substituted. That is exactly what is implemented here — the three conditions
    above and nothing else.

    The finding that produced the ruling stands recorded: §5.1.7's equation, the
    cofactored variant and the strict-canonical checks disagree on real edge-case
    signatures, so two verifiers both calling themselves conforming could return
    different answers for the same signature.
    """
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != PUBLIC_KEY_SIZE:
        raise Ed25519Error(f"public key must be {PUBLIC_KEY_SIZE} bytes")
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIGNATURE_SIZE:
        raise Ed25519Error(f"signature must be {SIGNATURE_SIZE} bytes")

    public_key = bytes(public_key)
    signature = bytes(signature)

    A = _decompress(public_key)
    if A is None:
        return False                                  # condition 1
    Rs = signature[:32]
    R = _decompress(Rs)
    if R is None:
        return False                                  # condition 1
    S = int.from_bytes(signature[32:], "little")
    if S >= _L:
        return False                                  # condition 2

    k = int.from_bytes(
        hashlib.sha512(Rs + public_key + message).digest(), "little"
    ) % _L
    return _point_equal(_scalar_mult(_B, S), _point_add(R, _scalar_mult(A, k)))  # condition 3
