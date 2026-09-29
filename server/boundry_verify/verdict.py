"""The verdict ladder — CP-008, ERR-CP-001/002 and ERR-P3-008, built in structurally.

*"The verdict ladder is where a mistake becomes a false public claim."*
This module is written so that over-claiming is **hard to express**, not merely
discouraged:

  * There is no `bool` verdict and no `.ok` attribute. A caller cannot reduce a
    result to a tick.
  * `not_established` is a REQUIRED constructor argument. A verdict that
    establishes something without saying what it does not establish cannot be
    constructed.
  * Every rendering — `str()`, `summary()`, `as_dict()` — carries the
    not-established clause. There is no short form that drops it.
  * The four outcomes are distinct and no code path converts one into another;
    a `Report` never promotes a weaker outcome upward.
  * Each non-ATTESTED outcome refuses, at construction, the words `ERR-P3-008`
    says it must never imply.
"""

from __future__ import annotations

import re
from typing import Sequence

__all__ = ["Outcome", "Verdict", "VerdictError", "Report", "INDETERMINATE",
           "ATTESTED", "UNATTESTED", "REFUTED", "ALTERED"]


class VerdictError(Exception):
    pass


class Outcome:
    """FOUR outcomes — `ERR-P3-008`, which added the one that was missing.

    T-2 had two failure outcomes for three epistemic states. That was
    reported; `ERR-P3-008` ruled it and supplied `REFUTED`:

      *"a supplied proof that fails and no proof at all are different epistemic
      states, and collapsing them either over-claims (calling absence a failure)
      or under-claims (calling a refutation mere absence)."*
    """

    #: The named check ran and passed, for exactly the scope stated.
    ATTESTED = "ATTESTED"

    #: Nothing attests to these bytes. **Never means the record is false.**
    UNATTESTED = "UNATTESTED"

    #: Evidence WAS supplied and failed. **Never means forged, and never means
    #: anyone acted in bad faith.** ERR-P3-008 is explicit that REFUTED inherits
    #: CP-008 in full: corrupted data, the wrong key, a truncated file and a
    #: deliberate forgery all produce it, and **it distinguishes none of them.**
    REFUTED = "REFUTED"

    #: A VALID attestation exists and the content no longer matches it.
    #: **Never means who altered it, or when.**
    ALTERED = "ALTERED"

    #: ⚠ ERR-P4-002 (DRAFT, — THE VERIFIER FAILED TO COMPLETE.
    #: The other four are claims ABOUT THE RECORD. This one is a claim about
    #: THIS INSTRUMENT, and it establishes NOTHING about the record either way.
    #:
    #: Our whole ladder presumes the verifier RETURNS. An unhandled exception
    #: returns nothing, and a caller wrapping the call in `try` reads a crash
    #: as a refusal -- so an instrument that broke and a record that failed
    #: become the same fact, and one of them is about us.
    INDETERMINATE = "INDETERMINATE"

    ALL = (ATTESTED, UNATTESTED, REFUTED, ALTERED, INDETERMINATE)


ATTESTED = Outcome.ATTESTED
UNATTESTED = Outcome.UNATTESTED
REFUTED = Outcome.REFUTED
ALTERED = Outcome.ALTERED
INDETERMINATE = Outcome.INDETERMINATE

# Words a verdict may never put in front of a non-ATTESTED result, per outcome.
# Enforced at construction, not by convention.
_FALSITY_WORDS = ("forged", "forgery", "fake", "falsified", "tampered",
                  "invalid", "false", "fraudulent", "counterfeit")
#: ERR-P3-008: REFUTED never means forged, and never imputes bad faith.
_BAD_FAITH_WORDS = ("bad faith", "deliberate", "dishonest", "malicious",
                    "deceit", "lied", "lying")
#: ERR-P3-008: ALTERED never says WHO altered it, or WHEN.
_ATTRIBUTION_WORDS = ("by the operator", "the operator altered", "who altered",
                      "attacker", "intruder")

#: Which word lists bind which outcome, and why. ⚠ Assembled at CALL time, not
#: at import: a first version snapshotted the tuples into a module-level dict,
#: so editing `_FALSITY_WORDS` changed nothing and a mutation of it read INERT.
#: That is `M12`'s dead-knob defect a second time, in a second file — a constant
#: that looks like configuration but was copied once. Read the source.
_OUTCOME_GUARDS = {
    UNATTESTED: (("_FALSITY_WORDS",),
                 "absence of attestation is never falsity (CP-008)"),
    REFUTED: (("_FALSITY_WORDS", "_BAD_FAITH_WORDS"),
              "REFUTED means evidence was given and failed; it never means forged "
              "and never imputes bad faith (ERR-P3-008)"),
    ALTERED: (("_ATTRIBUTION_WORDS", "_BAD_FAITH_WORDS"),
              "ALTERED never establishes who altered it, or when (ERR-P3-008)"),
}


def _forbidden_for(outcome):
    entry = _OUTCOME_GUARDS.get(outcome)
    if entry is None:
        return None
    names, why = entry
    words = ()
    for name in names:
        words += globals()[name]
    return words, why


class Verdict:
    __slots__ = ("rung", "outcome", "established", "not_established", "detail")

    def __init__(self, rung: str, outcome: str, *, established: Sequence[str],
                 not_established: Sequence[str], detail: str = "") -> None:
        if outcome not in Outcome.ALL:
            raise VerdictError(f"unknown outcome {outcome!r}")
        if not_established is None:
            raise VerdictError("not_established is required (ERR-CP-002)")
        established = tuple(established)
        not_established = tuple(not_established)
        if outcome == ATTESTED and not established:
            raise VerdictError("an ATTESTED verdict must say what it established")
        if not not_established:
            raise VerdictError(
                "every verdict must state what it did NOT establish (ERR-CP-002)"
            )
        forbidden = _forbidden_for(outcome)
        if forbidden is not None:
            words, why = forbidden
            blob = " ".join((detail,) + established).lower()
            for word in words:
                # ⚠ WORD BOUNDARIES, not substring. A plain `word in blob` test
                # fired on "supplied", which contains "lied" — so the guard
                # refused a correctly-worded REFUTED verdict whose detail read
                # "a receipt was supplied and is not well-formed".
                # This is 's lesson arriving in the implementation
                # rather than the test: a rule about what an output must SAY
                # cannot be enforced by naive substring matching either.
                if re.search(r"\b" + re.escape(word) + r"\b", blob):
                    raise VerdictError(
                        f"a {outcome} verdict may not use {word!r} — {why}")
        self.rung = rung
        self.outcome = outcome
        self.established = established
        self.not_established = not_established
        self.detail = detail

    def __bool__(self):
        # Deliberate. A caller that writes `if verdict:` is trying to collapse a
        # four-valued result into a tick, which is the CP-008 failure exactly.
        raise VerdictError(
            "a Verdict has no truth value: check `.outcome` against "
            "ATTESTED / UNATTESTED / REFUTED / ALTERED explicitly "
            "(CP-008)"
        )

    def summary(self) -> str:
        """The user-facing text. It ALWAYS carries the negative clause."""
        head = f"[{self.outcome}] {self.rung}"
        if self.detail:
            head += f" — {self.detail}"
        est = "\n".join(f"    established:     {e}" for e in self.established)
        nest = "\n".join(f"    NOT established: {n}" for n in self.not_established)
        return "\n".join(x for x in (head, est, nest) if x)

    __str__ = summary

    def as_dict(self) -> dict:
        return {
            "rung": self.rung,
            "outcome": self.outcome,
            "established": list(self.established),
            "not_established": list(self.not_established),
            "detail": self.detail,
        }


class Report:
    """An ordered set of verdicts. The overall reading is deliberately
    conservative and never upgrades."""

    def __init__(self) -> None:
        self.verdicts: list[Verdict] = []

    def add(self, verdict: Verdict) -> Verdict:
        self.verdicts.append(verdict)
        return verdict

    #: Strongest statement first. A weaker outcome never overrides a stronger
    #: one, and nothing is ever promoted upward to ATTESTED.
    #: ⚠ INDETERMINATE FIRST, and deliberately: if the instrument failed to
    #: complete, nothing it said before failing can be relied on -- so it must
    #: not be possible for a crashed run to report ALTERED or ATTESTED.
    PRECEDENCE = (INDETERMINATE, ALTERED, REFUTED, UNATTESTED, ATTESTED)

    @property
    def overall(self) -> str:
        outcomes = {v.outcome for v in self.verdicts}
        for outcome in self.PRECEDENCE:
            if outcome in outcomes:
                return outcome
        return UNATTESTED

    def summary(self) -> str:
        lines = [v.summary() for v in self.verdicts]
        lines.append(f"\nOVERALL: {self.overall}")
        lines.append("  " + _MEANING[self.overall])
        return "\n".join(lines)

    __str__ = summary


#: The one-line gloss printed under every overall result. ERR-P3-008's table,
#: including the "never means" column, because that column is the point.
_MEANING = {
    INDETERMINATE: "INDETERMINATE means: THIS VERIFIER FAILED TO COMPLETE. It is a "
                   "statement about the instrument, not about the record — nothing "
                   "has been established about these bytes in either direction, and "
                   "this is NOT a refusal (ERR-P4-002).",
    ATTESTED: "ATTESTED means: the stated checks passed, for exactly the scope "
              "each rung names — and no more.",
    UNATTESTED: "UNATTESTED means: nothing available attests to these bytes. It does "
                "NOT mean the record is false, forged or suspect (CP-008).",
    REFUTED: "REFUTED means: evidence WAS supplied and it failed. It does NOT mean "
             "the record is forged, and imputes bad faith to nobody — corrupted "
             "data, the wrong key, a truncated file and a deliberate forgery all "
             "produce this, and it distinguishes none of them (ERR-P3-008).",
    ALTERED: "ALTERED means: a valid attestation exists and the content no longer "
             "matches it. It does NOT establish who altered it, or when "
             "(ERR-P3-008).",
}


# --- the two rungs whose wording the errata govern ----------------------
def receipt_verdict(*, internally_sound: bool, signature_ok: bool,
                    detail: str = "") -> Verdict:
    """ERR-CP-001 verbatim: verifying a witness receipt establishes **two things
    and no third** — that the receipt is internally well-formed, and that it is
    signed by the key in the certificate it carries. It does NOT establish that
    the certificate belongs to a trusted authority.

    ERR-CP-002: an implementation MUST NOT present a receipt as verified without
    distinguishing these.

    ⚠ Retained for the general case. The ladder in `chain.py` uses a narrower
    form, because `ERR-P3-005` makes `witness_token` opaque and this verifier
    therefore cannot establish the SECOND of the two things — see
    `receipt.unverifiable_because` and.
    """
    never = (
        "that the certificate belongs to a trusted authority",
        "any trust chain to a trust anchor — chain-building and trust-anchor "
        "policy are the holder's, and are outside this specification",
        "that the signer is a party independent of the operator: a receipt an "
        "operator minted for themselves passes both checks above",
    )
    if internally_sound and signature_ok:
        return Verdict(
            "witness receipt", ATTESTED,
            established=("the receipt is internally well-formed",
                         "the receipt is signed by the key in the certificate it carries"),
            not_established=never, detail=detail)
    if not internally_sound:
        return Verdict("witness receipt", REFUTED, established=(),
                       not_established=never,
                       detail=detail or "the receipt is not well-formed")
    return Verdict("witness receipt", REFUTED, established=(),
                   not_established=never,
                   detail=detail or "the receipt's signature does not verify "
                                    "under the key in its own certificate")


def unwitnessed_verdict(reason: str = "no receipt was supplied") -> Verdict:
    """CP-008. The rung that is easiest to render as a red cross and must not be."""
    return Verdict(
        "witness receipt", UNATTESTED,
        established=(),
        not_established=(
            "when this record's head was seen by any party other than the operator",
            "any independent time binding — order and time rest on the operator alone",
        ),
        detail=f"unwitnessed ({reason}); this is not a finding against the record",
    )
