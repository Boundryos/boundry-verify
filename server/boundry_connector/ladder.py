"""The claim ladder that rides on every answer this connector gives.

`TEN-003` governs every sentence anyone says about the tenant slice, and
the connector's specification requires every tool's answer to carry what is PROVEN versus what is
ATTESTED. This module is the one place those sentences live, so a tool cannot
quietly say something stronger than the programme has earned.

⚠ **WHY THE LADDER IS IN THE PAYLOAD AND NOT ONLY IN THE DOCS.** A connector
answers a MODEL, and the model paraphrases before a human ever reads it. A
limit that lives in a README is a limit the paraphrase drops. A limit that
lives in the payload is one the paraphrase has to actively delete, and a
deletion is visible.

⚠ **LEAK-2: TOOL METADATA IS EXTERNAL WORDING.** A
tool's `description` is read by the model first and quoted back to the operator
in chat. The rule governs "records it renders" and did not reach the tool list.
Every description in `tools.py` is written to the interim-wording discipline and
none of them uses a strong form.
"""

from __future__ import annotations

__all__ = ["RUNTIME_WORDING", "TENANT_LADDER", "VERDICT_MEANINGS",
           "ladder_block", "NOT_ESTABLISHED"]

#: ⚠⚠ **THE SENTENCE EVERY ANSWER CARRIES, AND IT IS NOW PUBLIC AND
#: TRUE IN EVERY CONFIGURATION.** It read:
#:
#:     "Interim wording. This is a PRIVATE, single-operator, non-production instance running on
#:      synthetic material. Nothing here is an external claim."
#:
#: Three faults, and the third is the one that matters. *Interim* and *PRIVATE* are programme
#: words: they mean something inside the programme and nothing to a reviewer, who has just been
#: handed a public package. And **"running on synthetic material" is FALSE the moment a user
#: declares a folder of their own** — which the connector exists to let them do, and which the
#: privacy policy tells them to think carefully about first.
#:
#: > ***A STANDING SENTENCE ON EVERY ANSWER MUST BE TRUE IN EVERY CONFIGURATION THE PACKAGE
#: > ALLOWS, OR IT IS A SENTENCE THAT TEACHES THE READER TO SKIP IT.***
#:
#: The replacement says only what holds whatever is configured: the key custody, the deployment
#: shape, and which records are synthetic — the packaged ones, which are the only ones this
#: package ships. RENAMED with its sentence, declared old → new: `INTERIM_WORDING` →
#: `RUNTIME_WORDING`, and the block key `interim_wording` → `runtime_wording`, because a field
#: called *interim* is the same internal word in a machine-readable place.
RUNTIME_WORDING = (
    "Single-operator and non-production: one key signs these records and whoever runs this holds "
    "it. The packaged kit and demo records are synthetic."
)

#: `TEN-003`, carried verbatim in substance so no rung is climbed by forgetting
#: the ladder is one.
TENANT_LADDER = (
    "The mechanism partitions: on synthetic tenants, no measured read path "
    "crosses the boundary, and the cross-tenant vectors refuse. It is NOT "
    "'tenants are isolated in production'; NOT 'we cannot read your data' — "
    "one key signs for every tenant and the operator holds it; NOT 'proven "
    "against a hostile tenant'."
)

#: `ERR-P3-008` / `BV-028`, in the words a reader needs beside a verdict.
VERDICT_MEANINGS: dict[str, str] = {
    "ATTESTED": "evidence was supplied and it checked out.",
    "REFUTED": "evidence was supplied and it FAILED.",
    "ALTERED": "the bytes do not match what was recorded for them.",
    "UNATTESTED": ("nothing was evaluated — this states a gap in THIS reader, "
                   "never a finding against the record."),
}

#: What a Stage-1 answer never establishes, said every time rather than once.
NOT_ESTABLISHED: tuple[str, ...] = (
    "that any external party has witnessed this record",
    "that the operator's key custody is anything other than single-operator",
    "anything about a production deployment: this instance is non-production "
    "by construction and attaches to no live substrate",
)


def ladder_block(*, instrument: str, proven: list[str],
                 attested: list[str] | None = None,
                 tenant_scoped: bool = False) -> dict:
    """The block every tool result carries.

    `instrument` NAMES what produced the figures — the rule that caught the
    most in the connector-front rounds was the one requiring a figure to name
    which construction produced it.
    """
    block = {
        "instrument": instrument,
        "proven": list(proven),
        "attested": list(attested or []),
        "not_established": list(NOT_ESTABLISHED),
        "runtime_wording": RUNTIME_WORDING,
    }
    if tenant_scoped:
        block["tenant_claim_ladder"] = TENANT_LADDER
    return block
