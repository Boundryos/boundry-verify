"""`rsa_pkcs1` — RSASSA-PKCS1-v1_5 signature VERIFICATION, RFC 8017 §8.2.2.

⚠⚠ **Landing A.** The offline verifier implemented one
signature algorithm, Ed25519, so a token from any commercial timestamp authority
reached `tst-signature-algorithm-unsupported` and was never attempted. This
module is the RSA half of the repair.

⚠ **STANDARD LIBRARY ONLY** — guardrail 2, as `ed25519.py` honours it
and `boundry_verify/__init__.py` declares it. `hashlib` and `hmac`, and Python's
own `pow`. **No `cryptography`, no packages**, and the operator ruled on
15 September 2026 that the policy stands.

⚠⚠ **THE `DigestInfo` PREFIXES BELOW ARE TRANSCRIBED FROM RFC 8017 §9.2 NOTE 1
AND ARE NOT BELIEVED.** A mistyped prefix produces a verifier that refuses every
valid signature — or, worse, one that accepts a forgery — and reads correct
either way. Nothing here is trusted until a known-answer vector produced by an
INDEPENDENT ORACLE verifies under it. `VERIFIER/testing/rsa_pkcs1_vectors.json`
carries those vectors with the command that made each one.

⚠ **A MINIMUM MODULUS OF 2048 BITS IS THIS PACK'S POLICY, NOT A FACT ABOUT RSA.**
The operator ruled it on 15 September 2026. A 1024-bit signature that is
mathematically sound is REFUSED here BY NAME, and the vectors carry exactly that
case with the oracle's `OK` beside this module's refusal, so the difference
between *"the mathematics failed"* and *"this pack declines"* is on the record
rather than in a reader's head.

⚠ **K-3.** Import is definitions only: no I/O, no clock, no network.
"""

from __future__ import annotations

import hashlib
import hmac

__all__ = ["RsaError", "REFUSALS", "MIN_MODULUS_BITS", "DIGEST_INFO_PREFIXES",
           "verify"]

#: ⚠ The operator's ruling of 15 September 2026, stated as policy.
MIN_MODULUS_BITS = 2048

#: Every way this module declines, each by name. ⚠ A refusal that cannot be told
#: from another refusal is one finding wearing several names (`rfc3161.py`'s own
#: line, applied here).
REFUSALS: tuple[str, ...] = (
    "rsa-modulus-too-small",
    "rsa-exponent-invalid",
    "rsa-signature-length",
    "rsa-signature-out-of-range",
    "rsa-digest-unsupported",
)

#: ⚠⚠ **RFC 8017 §9.2 NOTE 1**, the full `DigestInfo` DER prefix for each hash.
#: These bytes are the one place a transcription error hides: the module still
#: imports, still runs, and returns False for everything. **The PASS vectors are
#: the proof, and they were produced by openssl rather than by this seat.**
DIGEST_INFO_PREFIXES: dict[str, bytes] = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


class RsaError(Exception):
    """A refusal, carrying its code so a caller can tell which one it is."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _i2osp(x: int, length: int) -> bytes:
    """RFC 8017 §4.1 — integer to octet string, fixed width."""
    return x.to_bytes(length, "big")


def verify(n: int, e: int, hash_name: str, message: bytes,
           signature: bytes) -> bool:
    """Does `signature` verify over `message` under the RSA public key `(n, e)`?

    RFC 8017 §8.2.2, in the specification's own step order. Returns True or
    False for a well-formed input; RAISES :class:`RsaError` when the input is
    one this module declines to attempt.

    ⚠ **THE DISTINCTION IS THE POINT** (`BV-028`): *"this signature does not
    verify"* and *"this pack will not attempt it"* are different facts about
    different parties, and a checker that returns False for both tells the
    operator nothing about which one happened.
    """
    if hash_name not in DIGEST_INFO_PREFIXES:
        raise RsaError("rsa-digest-unsupported",
                       f"this module performs {sorted(DIGEST_INFO_PREFIXES)} "
                       f"and was asked for {hash_name!r}")
    bits = n.bit_length()
    if bits < MIN_MODULUS_BITS:
        raise RsaError("rsa-modulus-too-small",
                       f"the modulus is {bits} bits; this pack requires "
                       f"{MIN_MODULUS_BITS} as a matter of POLICY ruled on "
                       "15 September 2026, not because the signature is unsound")
    if e < 3 or e % 2 == 0 or e >= n:
        raise RsaError("rsa-exponent-invalid",
                       f"the public exponent {e} is not an odd integer in "
                       "[3, n); RFC 8017 §3.1")

    k = (bits + 7) // 8
    if len(signature) != k:
        raise RsaError("rsa-signature-length",
                       f"the signature is {len(signature)} octet(s) and the "
                       f"modulus is {k}; RFC 8017 §8.2.2 step 1")

    # ── RSAVP1, RFC 8017 §5.2.2 ──────────────────────────────────────────
    s = int.from_bytes(signature, "big")
    if s >= n:
        raise RsaError("rsa-signature-out-of-range",
                       "the signature representative is not in [0, n-1]; "
                       "RFC 8017 §5.2.2 step 1")
    m = pow(s, e, n)
    em = _i2osp(m, k)

    # ── EMSA-PKCS1-v1_5-ENCODE, RFC 8017 §9.2 ────────────────────────────
    digest = hashlib.new(hash_name, message).digest()
    t = DIGEST_INFO_PREFIXES[hash_name] + digest
    if k < len(t) + 11:
        # §9.2 step 3. Unreachable at 2048 bits with SHA-512, and asserted
        # rather than assumed.
        raise RsaError("rsa-modulus-too-small",
                       f"the modulus is {k} octet(s) and the encoding needs "
                       f"{len(t) + 11}; RFC 8017 §9.2 step 3")
    ps = b"\xff" * (k - len(t) - 3)
    em_prime = b"\x00\x01" + ps + b"\x00" + t

    # ⚠ Constant-time comparison. A verifier is not a secret-holder, so this is
    # belt-and-braces rather than load-bearing — but `hmac.compare_digest` costs
    # nothing and a byte-by-byte `==` in a crypto path is the kind of thing a
    # reader has to stop and think about.
    return hmac.compare_digest(em, em_prime)
