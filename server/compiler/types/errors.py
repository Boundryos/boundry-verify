"""Phase 2 §2.6 — Compiler error taxonomy.

Every error in the catalogue has a structured exception class with stage,
severity, and recoverable flags. Errors terminate the request at the
originating stage; the Compiler never silently substitutes defaults
(BCL §8.3). The substrate's retry layer may retry transient errors; the
Compiler itself does not retry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Literal

Stage = Literal["parse", "resolve", "derive", "verify", "execute", "substrate"]
Severity = Literal["blocking", "transient"]

#: ⚠⚠ **THE NUMERIC BAND CARRIES NO AUTHORITY** (`WO-CON-45` V460, measured at
#: `R-352` §B3 and re-derived).
#:
#: A code's leading digit records **the stage section this file happened to
#: mint the class into**. It is **DECORATIVE**. The declared stage is
#: `STAGE_BY_CODE`'s and **only** `STAGE_BY_CODE`'s — that mapping is a
#: comprehension over `ALL_ERROR_CLASSES`, covered by a digest, and it is the
#: one place the stage is governed.
#:
#: > ***A NUMBER THAT LOOKS LIKE A DECLARATION AND GOVERNS NOTHING IS THE SAME
#: > DEFECT CLASS AS A LITERAL THAT LOOKS LIKE A RECORD AND SERVED 422.***
#:
#: ⚠ **A CLASS WHOSE CONDITION ARISES AT ONE STAGE AND WHOSE RECORD REPORTS
#: ANOTHER KEEPS THE BAND OF ITS CONDITION.** That is the rule, stated so the
#: next mint does not have to guess, and it is why the four below are not
#: errors to be corrected.
#:
#: **THE FOUR INSTANCES**, each declaring a stage whose band is not its own:
#:
#: * `COMP-ERR-305` `PrimitiveNotInAllowlist` — 3xx, declares `resolve`
#: * `COMP-ERR-306` `CheckPredicateNotInAllowlist` — 3xx, declares `resolve`
#: * `COMP-ERR-208` `MandatoryInvariantPredicateUnresolved` — 2xx, declares `verify`
#: * `COMP-ERR-209` `QueryChainSurfaceUnavailable` — 2xx, declares `execute`
#:
#: `COMP-ERR-511` agrees with its band and is **not** an instance.
#: ⚠ **The set is DERIVED, never counted here** — `tests/unit/
#: test_the_band_governs_nothing_v460.py` computes it from the classes, because
#: a figure typed into a comment goes stale where no instrument looks, which
#: this programme measured twice on 10 Sep 2026 alone.
#:
#: ⚠⚠ **AND ONE CORRECTION TO THIS SEAT'S OWN FIRST READING** (`R-359`).
#: A finding first reported *"five stage sections for six stages — `substrate`
#: has none"*. **The section was never absent.** It existed as
#: `# --- Substrate / infrastructure ---` and lacked only the
#: `Stage N: <stage>` **FORM**, so any instrument keying on that form counted
#: five and every 6xx class appeared to inherit the last `Stage` header —
#: which is `execute`. **The defect was in the naming, not the absence**, and
#: the fix was one line: `:610` now carries `Stage 6: substrate`, with its
#: width derived from its siblings. No class moved.
#:
#: > ***AN INSTRUMENT THAT KEYS ON A FORM REPORTS THE ABSENCE OF THE FORM AS
#: > THE ABSENCE OF THE THING.***
#:
#: ⚠ That is also why §B3's table put `COMP-ERR-208` and `-209` *"in
#: the execute section"*: they sat in the last **`Stage`** section, which was
#: `execute` only because `substrate`'s header lacked the form. **The
#: conclusion stood and the reason was luck** — now it is neither.
#:
#: ⚠ **NOTHING IS RENUMBERED**. These are published codes on an
#: outward-facing surface, and moving them to tidy a convention would be a wire
#: change made for neatness — worse than an unclear convention by every measure
#: this programme uses.
ErrorCode = Literal[
    "COMP-ERR-101",
    "COMP-ERR-102",
    "COMP-ERR-103",
    "COMP-ERR-104",
    "COMP-ERR-105",
    "COMP-ERR-106",
    "COMP-ERR-107",
    "COMP-ERR-201",
    "COMP-ERR-202",
    "COMP-ERR-203",
    "COMP-ERR-204",
    "COMP-ERR-205",
    "COMP-ERR-206",
    "COMP-ERR-208",
    "COMP-ERR-209",
    "COMP-ERR-301",
    "COMP-ERR-302",
    "COMP-ERR-303",
    "COMP-ERR-304",
    "COMP-ERR-305",
    "COMP-ERR-306",
    "COMP-ERR-401",
    "COMP-ERR-402",
    "COMP-ERR-403",
    "COMP-ERR-404",
    "COMP-ERR-405",
    "COMP-ERR-501",
    "COMP-ERR-502",
    "COMP-ERR-503",
    "COMP-ERR-504",
    "COMP-ERR-505",
    "COMP-ERR-506",
    "COMP-ERR-507",
    "COMP-ERR-508",
    "COMP-ERR-509",
    # `TenantContextRequired` carried this code and was in NEITHER the
    # `Literal` NOR `ALL_ERROR_CLASSES` — the sole difference between 44
    # code-carrying classes and 43 in each registry. **Both sets gain it
    # together**, because a two-way vector over one of them would pass
    # while the other stayed wrong.
    "COMP-ERR-510",
    # ⚠: the EXECUTE-stage
    # half of `COMP-ERR-305`. One class cannot declare two stages.
    "COMP-ERR-511",
    "COMP-ERR-513",
    "COMP-ERR-601",
    "COMP-ERR-602",
    "COMP-ERR-603",
    "COMP-ERR-604",
    "COMP-ERR-605",
    "COMP-ERR-606",
    "COMP-ERR-607",
    "COMP-ERR-608",
    "COMP-ERR-609",
    "COMP-ERR-610",
]


@dataclass(frozen=True)
class ErrorSpec:
    code: str
    name: str
    stage: Stage
    severity: Severity
    recoverable: bool


class CompilerError(Exception):
    """Base class for every Compiler error.

    Subclasses pin code/name/stage/severity/recoverable as class-level
    constants. Subclasses are instantiated with a structured `detail`
    string and optional `subject` mapping; neither carries domain meaning.
    """

    code: ClassVar[str] = ""
    name: ClassVar[str] = ""
    stage: ClassVar[Stage] = "parse"
    severity: ClassVar[Severity] = "blocking"
    recoverable: ClassVar[bool] = False

    # ⚠ **THE HINT IS A PROPERTY OF THE ERROR, NOT OF THE RAISE SITE**
    # Until now the four budget hints were typed at the
    # four `raise` sites in `determinism/budget.py`, which made the hint a
    # property of *where the error was raised* — so the same error raised from
    # a second site would carry a different hint, or none, and nothing would
    # say so. Pinned here it is one string per code, and
    # `assemble_replay_body` can resolve it from the code alone, with no
    # exception object in hand.
    #
    # `None` means this class declares no hint. It is `str | None` rather
    # than `""`-as-absent because *an empty hint is a hint that says nothing,
    # and a reader cannot tell it from a hint that was never written.*
    RECOVERY_HINT: ClassVar[str | None] = None

    def __init__(
        self,
        detail: str,
        subject: dict[str, str] | None = None,
        recovery_hint: str | None = None,
    ) -> None:
        super().__init__(f"[{self.code}] {self.name}: {detail}")
        self.detail = detail
        self.subject = dict(subject) if subject else {}
        # An explicitly passed hint still wins — the parameter is retained so
        # that a caller with something more specific than the class-level
        # sentence can say it. The class supplies the hint when nobody does.
        self.recovery_hint = recovery_hint or self.RECOVERY_HINT

    def to_spec(self) -> ErrorSpec:
        return ErrorSpec(
            code=self.code,
            name=self.name,
            stage=self.stage,
            severity=self.severity,
            recoverable=self.recoverable,
        )


# --- Stage 1: parse ---------------------------------------------------------


class IntentHashMismatch(CompilerError):
    code = "COMP-ERR-101"
    name = "intent_hash_mismatch"
    stage = "parse"
    severity = "blocking"
    recoverable = True


class IntentGrammarInvalid(CompilerError):
    code = "COMP-ERR-102"
    name = "intent_grammar_invalid"
    stage = "parse"
    severity = "blocking"
    recoverable = True


class IntentKindUnknown(CompilerError):
    code = "COMP-ERR-103"
    name = "intent_kind_unknown"
    stage = "parse"
    severity = "blocking"
    recoverable = True


class IntentVersionUnknown(CompilerError):
    code = "COMP-ERR-104"
    name = "intent_version_unknown"
    stage = "parse"
    severity = "blocking"
    recoverable = False


class SubmitterInvalid(CompilerError):
    code = "COMP-ERR-105"
    name = "submitter_invalid"
    stage = "parse"
    severity = "blocking"
    recoverable = True


class RequestEnvelopeMalformed(CompilerError):
    code = "COMP-ERR-106"
    name = "request_envelope_malformed"
    stage = "parse"
    severity = "blocking"
    recoverable = True


class BclVersionNotAccepted(CompilerError):
    # SUBSTRATE-VNEXT T04 (BCL NOTE-2): the manifest's accepted_bcl_versions is a
    # load-bearing admission gate at parse — a bcl_version outside the manifest's
    # accepted set is rejected structurally, not left to the grammar router.
    code = "COMP-ERR-107"
    name = "bcl_version_not_accepted"
    stage = "parse"
    severity = "blocking"
    recoverable = True


# --- Stage 2: resolve -------------------------------------------------------


class ContractVersionUnresolved(CompilerError):
    code = "COMP-ERR-201"
    name = "contract_version_unresolved"
    stage = "resolve"
    severity = "blocking"
    recoverable = True


class ArtefactHashMismatch(CompilerError):
    code = "COMP-ERR-202"
    name = "artefact_hash_mismatch"
    stage = "resolve"
    severity = "blocking"
    recoverable = True


class ContractPinIncomplete(CompilerError):
    code = "COMP-ERR-203"
    name = "contract_pin_incomplete"
    stage = "resolve"
    severity = "blocking"
    recoverable = True


class AgentVersionUnresolved(CompilerError):
    code = "COMP-ERR-204"
    name = "agent_version_unresolved"
    stage = "resolve"
    severity = "blocking"
    recoverable = True


class DataBindingUniqueNameViolation(CompilerError):
    code = "COMP-ERR-205"
    name = "data_binding_unique_name_violation"
    stage = "resolve"
    severity = "blocking"
    recoverable = True


class ArtefactIdConflict(CompilerError):
    """⚠ **A PUT TO AN EXISTING `artefact_id` WITH DIFFERENT BYTES**

    The kernel-facing name for the substrate's `ArtefactIdBodyConflict`. The
    store is content-addressed and an `artefact_id` names ONE body for ever;
    re-putting the same id with different bytes is neither an update nor
    idempotent.

    > ***AN IDENTITY THAT CAN BE REPOINTED IS NOT AN IDENTITY; IT IS A MUTABLE
    > NAME, AND EVERY RECORD THAT CITED IT IS NOW CITING SOMETHING ELSE.***

    `stage = "resolve"` — where a binding's artefact is looked up and where a
    caller publishing one is refused. `recoverable` is **True**: the caller has
    an id it does not own the history of, and a fresh id is the recovery, which
    is the same shape gave a rejected request.
    """

    code = "COMP-ERR-206"
    name = "artefact_id_conflict"
    stage = "resolve"
    severity = "blocking"
    recoverable = True
    RECOVERY_HINT = "Publish the body under a new artefact_id."


# --- Stage 3: derive --------------------------------------------------------


class IntentToPlanFailed(CompilerError):
    code = "COMP-ERR-301"
    name = "intent_to_plan_failed"
    stage = "derive"
    severity = "blocking"
    recoverable = False


class CompositionSizeExceeded(CompilerError):
    code = "COMP-ERR-302"
    name = "composition_size_exceeded"
    stage = "derive"
    severity = "blocking"
    recoverable = True


class AdvisoryMaterialisationMismatch(CompilerError):
    code = "COMP-ERR-303"
    name = "advisory_materialisation_mismatch"
    stage = "derive"
    severity = "blocking"
    recoverable = False


class AdvisorySourceNotPermitted(CompilerError):
    code = "COMP-ERR-304"
    name = "advisory_source_not_permitted"
    stage = "derive"
    severity = "blocking"
    recoverable = True


class PrimitiveNotInAllowlist(CompilerError):
    """⚠ **`stage` MOVED `derive` → `resolve` AT `C1a`** (ruled
    ); the finding is 's.

    A primitive absent from the manifest allowlist is caught in **resolve**,
    which emits `compiler.resolve_failed` — while this class declared
    `derive`. So the caller was told one stage and the record said another.

    > ***A STAGE NAMED ON THE ERROR AND A STAGE NAMED BY THE ENVELOPE ARE TWO
    > ANSWERS TO WHERE IT HAPPENED, AND THE ERROR'S FOLLOWS THE RECORD.***

    ⚠ **THE SECOND RAISE SITE HAS BEEN SPLIT OFF** (
    ). `compiler/sandbox/primitives.py` `dispatch` raised this
    same class when a primitive has no Wave-1 runtime implementation — during
    EXECUTE, not resolve — so one class with one declared `stage` had two sites
    that could not both be right. That site now raises
class:`PrimitiveRuntimeImplementationMissing` (`COMP-ERR-511`) and **this
    class has one site, `compiler/stages/resolve.py:223`, at the stage it
    declares.**
    """

    code = "COMP-ERR-305"
    name = "primitive_not_in_allowlist"
    stage = "resolve"
    severity = "blocking"
    recoverable = False


class CheckPredicateNotInAllowlist(CompilerError):
    """KERNEL-CHECK-W5 — a CHECK plan referenced a (predicate_id,
    predicate_version) absent from the manifest's
    ``check_predicate_allowlist``. Raised at resolve. Not recoverable:
    the manifest is the source of truth for executable predicates."""

    # COMP-ERR-303 is already taken by AdvisoryMaterialisationMismatch
    # (the W5 ticket pack mis-cited it). Using the next free resolve-
    # stage code 306; documented in the W5 PR.
    code = "COMP-ERR-306"
    name = "check_predicate_not_in_allowlist"
    stage = "resolve"
    severity = "blocking"
    recoverable = False


# --- Stage 4: verify --------------------------------------------------------


class InvariantFailed(CompilerError):
    code = "COMP-ERR-401"
    name = "invariant_failed"
    stage = "verify"
    severity = "blocking"
    recoverable = False


class SchemaFailed(CompilerError):
    code = "COMP-ERR-402"
    name = "schema_failed"
    stage = "verify"
    severity = "blocking"
    recoverable = False


class BudgetZeroOrNegative(CompilerError):
    code = "COMP-ERR-403"
    name = "budget_zero_or_negative"
    stage = "verify"
    severity = "blocking"
    recoverable = True


class MetaInvariantFailed(CompilerError):
    code = "COMP-ERR-404"
    name = "meta_invariant_failed"
    stage = "verify"
    severity = "blocking"
    recoverable = False


class InvariantsEmpty(CompilerError):
    code = "COMP-ERR-405"
    name = "invariants_empty"
    stage = "verify"
    severity = "blocking"
    recoverable = False


# --- Stage 5: execute -------------------------------------------------------


class TransformFailed(CompilerError):
    code = "COMP-ERR-501"
    name = "transform_failed"
    stage = "execute"
    severity = "blocking"
    recoverable = False


class BudgetExceededWallTime(CompilerError):
    code = "COMP-ERR-502"
    name = "budget_exceeded_wall_time"
    stage = "execute"
    severity = "blocking"
    recoverable = True
    RECOVERY_HINT = "Raise budget.wall_time_ms."


class BudgetExceededCPU(CompilerError):
    code = "COMP-ERR-503"
    name = "budget_exceeded_cpu"
    stage = "execute"
    severity = "blocking"
    recoverable = True
    RECOVERY_HINT = "Raise budget.cpu_ms."


class BudgetExceededMemory(CompilerError):
    code = "COMP-ERR-504"
    name = "budget_exceeded_memory"
    stage = "execute"
    severity = "blocking"
    recoverable = True
    RECOVERY_HINT = "Raise budget.memory_bytes."


class BudgetExceededIO(CompilerError):
    code = "COMP-ERR-505"
    name = "budget_exceeded_io"
    stage = "execute"
    severity = "blocking"
    recoverable = True
    RECOVERY_HINT = "Raise budget.io_bytes."


class SandboxViolation(CompilerError):
    code = "COMP-ERR-506"
    name = "sandbox_violation"
    stage = "execute"
    severity = "blocking"
    recoverable = False


class OutputArtefactInvariantFailed(CompilerError):
    code = "COMP-ERR-507"
    name = "output_artefact_invariant_failed"
    stage = "execute"
    severity = "blocking"
    recoverable = False


class QueryHeadUnknown(CompilerError):
    """BOUNDRYDB-3A-QUERY — the QUERY's chain_head_hash does not resolve to any
    prefix of the current chain (an unknown / un-pinnable head)."""

    code = "COMP-ERR-508"
    name = "query_head_unknown"
    stage = "execute"
    severity = "blocking"
    recoverable = False


class ProjectionRefUnresolved(CompilerError):
    """BOUNDRYDB-3A-QUERY — the QUERY's projection_ref does not resolve to a
    known projection definition."""

    code = "COMP-ERR-509"
    name = "projection_ref_unresolved"
    stage = "execute"
    severity = "blocking"
    recoverable = False


class TenantContextRequired(CompilerError):
    """BOUNDRYDB-3B — a QUERY over a per_tenant schema was submitted without the
    required tenant context (cross-tenant isolation is structural, not policy)."""

    code = "COMP-ERR-510"
    name = "tenant_context_required"
    stage = "execute"
    severity = "blocking"
    recoverable = False


class PrimitiveRuntimeImplementationMissing(CompilerError):
    """⚠ **THE EXECUTE-STAGE HALF OF `COMP-ERR-305`** (
the finding is 's ).

    `PrimitiveNotInAllowlist` was raised at TWO stages by ONE class carrying ONE
    declared `stage`. `compiler/stages/resolve.py:223` raises it when a primitive
    is absent from the manifest allowlist — caught in **resolve**, which is what
    the class declares. `compiler/sandbox/primitives.py` `dispatch` raised the
    same class when an allowlisted primitive has no Wave-1 runtime
    implementation — which happens during **execute**.

    > ***ONE CLASS RAISED AT TWO STAGES CANNOT DECLARE ONE.***

    They are also two different faults. Absent from the allowlist is a PLAN the
    manifest does not permit; no runtime body for a primitive the manifest DOES
    permit is a CONFIGURATION defect on the serving side — the allowlist and the
    implementation table disagree, and the caller did nothing wrong.

    `COMP-ERR-305` keeps `resolve` and its one remaining site; this carries the
    execute-stage site. `severity` and `recoverable` are the class it leaves.
    """

    code = "COMP-ERR-511"
    name = "primitive_runtime_implementation_missing"
    stage = "execute"
    severity = "blocking"
    recoverable = False


class AgentRuntimeImplementationMissing(CompilerError):
    """⚠ **THE EXECUTE-STAGE HALF OF `COMP-ERR-204`** (
    §5(c)), built by the same argument that split `COMP-ERR-305` at
      — and deliberately, because the analogy is the
    whole reason this class exists rather than a wider `AgentVersionUnresolved`.

    `AgentVersionUnresolved` is raised when an agent is not resolvable for the
    PLAN: the version was never pinned, or the registry does not carry it. That
    is caught at **resolve**, which is what the class declares.

    This is a different fault at a different stage. The agent IS permitted —
    registry and manifest resolved it — and has **no runtime body** in
    `AGENT_IMPLEMENTATIONS`. The permission surface and the implementation
    table disagree, during **execute**, and the caller did nothing wrong.

    > ***PERMISSION AND BODY ARE DIFFERENT FAULTS AT DIFFERENT STAGES.***

    ⚠ **`AgentVersionUnresolved` IS NOT DELETED OR NARROWED.** An unpinned or
    unregistered agent is still an unresolved version and still raises it
this order does not remove a correct refusal to
    make room for a new one. What changes is that a configuration defect on the
    serving side stops borrowing a resolve-stage class to report itself.

    ⚠⚠ **THE NUMBER SKIPS 512, AND THE SKIP IS THE POINT.** `COMP-ERR-512`
    is not free — it is REFUSED. weighed it for
    `IntentToPlanFailed`'s composition arm and declined it on the rule that
    *the same condition reached by a different code path is one condition*,
    and `tests/unit/test_the_condition_splits_v458.py` carries it in
    `REFUSED_CODES` so the refusal is enforced rather than remembered.

    > ***A REFUSED CODE IS NOT A FREE CODE. IT IS A DECISION RECORDED AS A
    > GAP.*** This class was first written as 512 by scanning the codes IN USE
    > and never the codes REFUSED; caught it on the first run, which is
    > what that vector exists for.

     is not overruled here and this class does not test its rule:
    permission-versus-body is a different CONDITION at a different STAGE, not
    the same condition down a second code path — the distinction `COMP-ERR-511`
    was minted on.
    """

    code = "COMP-ERR-513"
    name = "agent_runtime_implementation_missing"
    stage = "execute"
    severity = "blocking"
    recoverable = False


class MandatoryInvariantPredicateUnresolved(CompilerError):
    """⚠ **A SECOND CONDITION SPLIT OFF `COMP-ERR-401` — ON THE CONDITION, NOT
    THE STAGE**.

    `InvariantFailed` at `compiler/stages/verify.py:245`
    `_evaluate_plan_invariants` is **an invariant that failed**. At
    `compiler/stages/resolve.py:339` `_resolve_invariants` the condition was **a
    predicate required by a mandatory invariant not being found in the
    registry** — nothing was evaluated and no invariant failed.

    > ***A CALLER TOLD `invariant_failed` LOOKS FOR A FAILING PREDICATE THAT RAN.
    > THE STAGE IS THE SYMPTOM AND THE CONDITION IS THE DEFECT.***

    ⚠ **`stage` IS TAKEN FROM THE RECORD AND NOT FROM THE CALL PATH.**
    measured `recorded=verify` at that site, so this class declares `verify` —
    the same stage its parent declares. **The split moves no stage at all**; it
    moves only which class names the condition, which is why it survived
     's withdrawal. A declaration taken from
    `static=` is what the withdrawn limb was doing.
    """

    code = "COMP-ERR-208"
    name = "mandatory_invariant_predicate_unresolved"
    stage = "verify"
    severity = "blocking"
    recoverable = False


class QueryChainSurfaceUnavailable(CompilerError):
    """⚠ **A SECOND CONDITION SPLIT OFF `COMP-ERR-501` — ON THE CONDITION, NOT
    THE STAGE**.

    `TransformFailed` has eight sites in `compiler/stages/execute.py` where a
    transform genuinely fails. At `compiler/stages/query_execution.py:55`
    `_chain_reader` the condition is that the emitter has **no substrate-backed
    envelope chain** — a QUERY needs a global cross-request read surface and the
    in-memory emitter has none. **No transform was attempted.**

    > ***A CALLER TOLD `transform_failed` LOOKS FOR A TRANSFORM. NEITHER
    > EXISTS.***

    ⚠ **`stage` FROM THE RECORD**: measured `recorded=execute` at that
    site, so this class declares `execute`, as its parent does. As with
    `COMP-ERR-208`, no stage moves.
    """

    code = "COMP-ERR-209"
    name = "query_chain_surface_unavailable"
    stage = "execute"
    severity = "blocking"
    recoverable = False


# --- Stage 6: substrate -----------------------------------------------------


class SubstrateUnavailable(CompilerError):
    code = "COMP-ERR-601"
    name = "substrate_unavailable"
    stage = "substrate"
    severity = "transient"
    recoverable = True


class CompilerVersionMismatch(CompilerError):
    code = "COMP-ERR-602"
    name = "compiler_version_mismatch"
    stage = "substrate"
    severity = "blocking"
    recoverable = True


class SubstrateVersionMismatch(CompilerError):
    code = "COMP-ERR-603"
    name = "substrate_version_mismatch"
    stage = "substrate"
    severity = "blocking"
    recoverable = True


class RegistryReadFailed(CompilerError):
    code = "COMP-ERR-604"
    name = "registry_read_failed"
    stage = "substrate"
    severity = "transient"
    recoverable = True


class EnvelopeEmissionFailed(CompilerError):
    """⚠ **RAISED FOR THE FIRST TIME ** (option D).
    Declared since the error vocabulary was written and raised **nowhere** —
    *a declared class nobody raises is a door nobody has opened.*

    It is raised at the **success**-emit sites only. `_emit_or_record` keeps
    swallow-and-log on the FAILURE arms, because there the outcome is already
    failure and the log line records the missing envelope. On a SUCCESS arm
    swallowing would serve a `CompilationResult` with no
    `compiler.execution_succeeded` on the chain, which is 's own
    nightmare manufactured by the repair.

    > ***THE WORK SUCCEEDED; THE RECORD OF IT COULD NOT BE WRITTEN. THE RECORD
    > GOVERNS, SO A SUCCESS WITH NO RECORD IS NOT A SUCCESS THIS SYSTEM CAN
    > STAND BEHIND.***

    ⚠ **`recoverable` MOVED `False` → `True`, AND THE MEASUREMENT CAME FIRST**
    (which required it measured and not assumed).

    Measured across `compiler/`, `substrate/` and `manifest/` by `ast`:
    **nothing branches on `recoverable`** — no `if`, `while`, ternary or
    `assert` anywhere tests it. Every consumer CARRIES it, and three of those
    are client-facing: `compiler/api/server.py:495` (`CompilerError`
    handler's body), `compiler/api/routes_artefacts.py:131` (a 409 body) and
    `compiler/api/replay_body.py:174` (replay body). It is also one of the
    seven registered `compiler.request_closed` payload keys
    (`envelope_emitter.py:160`).

    So it governs **nothing inside the kernel** and is **advisory on the wire** —
    which is a third category, not the decorative one: the numeric code band is
    read by nobody, while this is served to every client.

    ⚠ **AND THE OLD VALUE WOULD HAVE PUT TWO ANSWERS ON ONE WIRE.** `stage` is
    `substrate`, which `_stage_to_status` maps to **503 — the surface is down,
    retry** — while `recoverable: false` says *do not*. caught that
    before it shipped. The work succeeded and only its recording failed, so
    retrying is exactly right and the field now agrees with the status.
    """

    code = "COMP-ERR-605"
    name = "envelope_emission_failed"
    stage = "substrate"
    severity = "blocking"
    recoverable = True


class ClosureWithoutFailureEnvelope(CompilerError):
    """⚠ **A CLOSURE THAT RECORDS A REJECTION NOTHING ON THE CHAIN CAUSED**

    Raised by `_close_request` when it is asked to close a request with an
    outcome of `rejected`, `execution_failed` or `execution_aborted` and the
    chain carries no `*_failed` or `*_aborted` envelope before it.

    ⚠ **WHY THIS IS AN ERROR AND NOT A DEFAULT.** The closure reads
    `recoverable` off the chain's last failure envelope, and with none present
    it wrote `false` — a plausible value, on a chain that says a request was
    rejected for no recorded reason. Nothing downstream could tell that apart
    from a genuine non-recoverable failure:

    > ***A RECORD THAT CAN STATE AN OUTCOME IT HAS NO EVIDENCE FOR IS A RECORD
    > WHOSE OUTCOMES ARE NOT EVIDENCE.***

    `stage` is `substrate` and the code sits in the `60x` family with the other
    record-integrity errors: this is not a fault in the request, it is the
    kernel about to write a chain that contradicts itself.
    """

    code = "COMP-ERR-606"
    name = "closure_without_failure_envelope"
    stage = "substrate"
    severity = "blocking"
    recoverable = False



class ClosurePayloadNotTheRegisteredSet(CompilerError):
    """⚠ **ONE KIND, ONE SHAPE**.

    Raised by the emitter when a `compiler.request_closed` payload's keys are
    not exactly `CLOSING_PAYLOAD_KEYS`.

    ⚠ **WHY THE EMITTER AND NOT THE CALLER.** The closure is built in one place
    and every reader of the record — the replay body, `is_chain_over`, the
    programme's rosters — reads it by key. A second construction with a
    different shape would not fail anywhere: it would be *a closure with a
    missing field*, and every reader would answer for it with a default.

    > ***A KIND WHOSE SHAPE IS ENFORCED NOWHERE IS A KIND WHOSE READERS EACH
    > CARRY A DIFFERENT GUESS ABOUT IT.***

    Missing keys and extra keys are both refused, and for the same reason: the
    set is what a reader is entitled to assume, so a payload that carries less
    breaks the assumption and one that carries more makes it stop being true
    of the kind.

    `stage` is `substrate` and the code sits in the `60x` family with the other
    record-integrity errors — the request is not at fault; the kernel is about
    to write an envelope its own readers cannot rely on.
    """

    code = "COMP-ERR-607"
    name = "closure_payload_not_the_registered_set"
    stage = "substrate"
    severity = "blocking"
    recoverable = False



class PlanBodyConflictAtSeal(CompilerError):
    """⚠ **A PLAN ID THAT ALREADY NAMES OTHER BYTES** (
    ).

    Raised by `seal` when the artefact store refuses the plan body because
    `micro_contract_id` is already bound to different bytes. The store's
    refusal is `ArtefactIdBodyConflict`; this is the
    kernel's code for it, translated at the boundary — 's seam:
    *the substrate's exception, the kernel's code, the translation where they
    meet, and never a substrate exception travelling up a kernel surface.*

    ⚠ **WHY THE SEAL FAILS RATHER THAN CONTINUING.** The envelope's
    `content_hash` is a pointer into the store. If the put is refused and the
    seal proceeds, the record gains a pointer to bytes that are not there —
    which is the exact state exists to remove, reintroduced at the one
    moment it would look like an ordinary success.

    `stage` is `substrate`: the request is not at fault.
    """

    code = "COMP-ERR-608"
    name = "plan_body_conflict_at_seal"
    stage = "substrate"
    severity = "blocking"
    recoverable = False



class SealedPayloadNotTheRegisteredSet(CompilerError):
    """⚠ **AN ENVELOPE THAT SAYS A PLAN WAS SEALED WHERE NONE WAS**

    Raised by the emitter when a `compiler.micro_contract_sealed` payload's
    keys are not exactly `SEALED_PAYLOAD_KEYS`.

     counted 211 such envelopes against 202 seals; the trace named the
    difference as ten emits at three sites, all test fixtures building chain
    shapes. The kind's meaning is that `seal` ran — and after that also
    means a body is on the record under the hash this payload carries. An
    envelope of this kind with neither is a claim about a seal nobody made.

    `stage` is `substrate`, in the `60x` record-integrity family.
    """

    code = "COMP-ERR-609"
    name = "sealed_payload_not_the_registered_set"
    stage = "substrate"
    severity = "blocking"
    recoverable = False



class PlanSealUnverified(CompilerError):
    """⚠ **THE RECORD'S OWN SEAL DOES NOT STAND UP** (
).

    The kernel-facing name for the substrate's three plan-seal refusals —
    `PlanBodyAbsent` (SUBSTRATE-VERIFY-103), `PlanSealAbsent` (104) and
    `PlanSealInvalid` (105) — translated at the boundary, 's seam:
    *the substrate's exception, the kernel's code, the translation where they
    meet, and never a substrate exception travelling up a kernel surface.*

    The substrate's own code travels in `subject["substrate_code"]`, because
    the three absences are not one condition and a caller that must repair one
    of them needs to know which.

    ⚠ **WHY ONE KERNEL CODE FOR THREE SUBSTRATE ONES.** The kernel's taxonomy
    answers "what should the caller do?", and the answer is the same for all
    three: *do not treat this chain's plan as sealed.* The substrate's answers
    "what is wrong with the record?", which is three different things.

    `stage` is `substrate`: the request is not at fault, the record is.
    """

    code = "COMP-ERR-610"
    name = "plan_seal_unverified"
    stage = "substrate"
    severity = "blocking"
    recoverable = False


ALL_ERROR_CLASSES: tuple[type[CompilerError], ...] = (
    IntentHashMismatch,
    IntentGrammarInvalid,
    IntentKindUnknown,
    IntentVersionUnknown,
    SubmitterInvalid,
    RequestEnvelopeMalformed,
    BclVersionNotAccepted,
    ContractVersionUnresolved,
    ArtefactHashMismatch,
    ContractPinIncomplete,
    AgentVersionUnresolved,
    DataBindingUniqueNameViolation,
    IntentToPlanFailed,
    CompositionSizeExceeded,
    AdvisoryMaterialisationMismatch,
    AdvisorySourceNotPermitted,
    PrimitiveNotInAllowlist,
    CheckPredicateNotInAllowlist,
    InvariantFailed,
    SchemaFailed,
    BudgetZeroOrNegative,
    MetaInvariantFailed,
    InvariantsEmpty,
    TransformFailed,
    BudgetExceededWallTime,
    BudgetExceededCPU,
    BudgetExceededMemory,
    BudgetExceededIO,
    SandboxViolation,
    OutputArtefactInvariantFailed,
    QueryHeadUnknown,
    ProjectionRefUnresolved,
    # ⚠: absent here as well as from the `Literal`.
    # `ALL_ERROR_CODES`, `ERROR_CLASS_BY_CODE` and `STAGE_BY_CODE` are all
    # DERIVED from this tuple, so one line repairs four registries — and
    # `ERROR_CLASS_BY_CODE.get("COMP-ERR-510")` returning `None` is what
    # caught the wrong `ast` pass.
    TenantContextRequired,
    # ⚠: the execute-stage half of `COMP-ERR-305`.
    PrimitiveRuntimeImplementationMissing,
    AgentRuntimeImplementationMissing,
    # ⚠: two classes carrying two CONDITIONS
    # each. Neither moves a stage — each declares what its record reports.
    MandatoryInvariantPredicateUnresolved,
    QueryChainSurfaceUnavailable,
    SubstrateUnavailable,
    CompilerVersionMismatch,
    SubstrateVersionMismatch,
    ArtefactIdConflict,
    RegistryReadFailed,
    EnvelopeEmissionFailed,
    ClosureWithoutFailureEnvelope,
    ClosurePayloadNotTheRegisteredSet,
    PlanBodyConflictAtSeal,
    SealedPayloadNotTheRegisteredSet,
    PlanSealUnverified,
)

ALL_ERROR_CODES: tuple[str, ...] = tuple(cls.code for cls in ALL_ERROR_CLASSES)

ERROR_CLASS_BY_CODE: dict[str, type[CompilerError]] = {cls.code: cls for cls in ALL_ERROR_CLASSES}


def recovery_hint_for_code(code: str) -> str | None:
    """The recovery hint declared by the error class carrying `code`.

    ⚠ **THE HINT IS RESOLVED WITHOUT AN EXCEPTION OBJECT** (
    ). `assemble_replay_body` builds a rejection body out of a chain
    of envelopes, and no envelope on that chain carries a hint — the hint was
    never emitted, in any kind, at any position. Before this, that was the one
    field standing between a rejection body and the record:

    > ***A FIELD THAT IS A FACT OF THE ERROR CLASS DOES NOT HAVE TO BE ON THE
    > RECORD TO BE SERVED FROM IT; IT HAS TO BE DERIVABLE FROM SOMETHING THAT
    > IS.***

    The `error_code` IS on the record, and the code determines the class, and
    the class declares the hint. So a replayed budget overrun is served the
    same sentence a live one was, with neither the chain nor the cache ever
    having held it.

    ⚠ **AN UNKNOWN CODE RESOLVES TO `None`, IT DOES NOT RAISE.** A body being
    assembled from a durable chain may carry a code minted after that chain was
    written, or one since retired. That is a reason to serve the body without a
    hint, never a reason to refuse to serve the body — *a replay that fails
    because it could not decorate itself has lost the thing it was for.*
    """
    cls = ERROR_CLASS_BY_CODE.get(code)
    return cls.RECOVERY_HINT if cls is not None else None


#: ⚠ **THE CODES THAT DECLARE A HINT**, computed, never typed. A typed list
#: would be a second place for the answer to differ from the classes.
CODES_WITH_RECOVERY_HINT: tuple[str, ...] = tuple(
    code for code, cls in ERROR_CLASS_BY_CODE.items() if cls.RECOVERY_HINT
)


#: ⚠ **EVERY ERROR'S DECLARED STAGE, COMPUTED FROM THE CLASSES** (`C1a`,
#: and it was ruled so.
#:
#: The ruling asked for `COMP-ERR-305`'s stage to move "as a vocabulary row
#: move v2 with its cascade". **There was no row.** `ALL_ERROR_CODES` is
#: digested over the codes and `ALL_ERROR_CLASSES` over the classes' qualified
#: names, so an error's `stage` — a published field every rejection body
#: carries — was governed by nothing, and could only find its
#: disagreement with the record by reading.
#:
#: > ***A FIELD ON A PUBLIC SURFACE THAT NO DIGEST COVERS CAN BE EDITED WITHOUT
#: > ANYTHING SAYING SO, AND "IT MOVED" IS THEN A CLAIM RATHER THAN A
#: > MEASUREMENT.***
#:
#: So the row is MINTED here at v1 rather than a v2 being moved, and
#: says that plainly: the instruction anticipated a row this register did not
#: have. From here a stage cannot change without its digest moving.
#:
#: **Computed, never typed** — a class whose stage is edited moves this digest
#: without anyone remembering to edit a tuple, which is the whole point.
#: ⚠ `dict(...)` and not a dict COMPREHENSION: the sweep's discovery reads
#: shapes by `ast`, and `_CONSTRUCTORS` recognises a constructor call where a
#: `DictComp` is not collection-shaped to it. Written as a comprehension the
#: row registered and then refused `register-row-without-home` — *a row whose
#: home the instrument cannot see is a row governing nothing.*
STAGE_BY_CODE: dict[str, str] = dict(
    (cls.code, cls.stage) for cls in ALL_ERROR_CLASSES
)
