"""The tenant gate on the CONNECTOR's OWN read path — `TEN-002`, owed honestly.

⚠ **WHY THIS MODULE EXISTS AT ALL.** A measurement found that
`routes_envelopes.py`, `routes_replay.py`, `streaming.py` and
`envelope_view.py` return envelopes and consult NO tenant discriminator, and
a ruling accepted the correction that a schema declaration enforces nothing —
**enforcement lives on the read path**. A connector that wraps those four
surfaces inherits four unenforced read paths. So the connector adds the
enforcement on ITS path, here, and every envelope-returning tool goes through
this function or does not answer.

⚠ **THE FILTER IS IMPORTED, NEVER RE-TYPED.** `_apply_tenant_scope` lives at
`compiler/stages/tenant_scope.py` and has exactly one call site in canon.
Copying its four lines here would make TWO enforcement sites for one rule, and
two sites for one rule is the thing that drifts. `SEAT-001`'s shape applied to
a boundary rather than to a path: *defined once, derived everywhere else.*

⚠ **ABSENCE REFUSES, AND THAT IS THE WHOLE POINT.** `TEN-002(a)`: a selector
that declares nothing was silently omniscient, and the cure was to refuse.
⚠ **THIS SENTENCE WENT FALSE AND THE SWEEP CAUGHT IT.**
It read *"`auth.py` STILL HAS the opposite default in two places"* — an envelope
with no `submitter_principal_id`, and a body with no `submitter_domain_ref`,
readable by anyone authenticated. **That was true when written and is not true
now.** Both were CLOSED: when this was measured,
`check_envelope_read_authority` returns `False` on an absent
`submitter_principal_id` and `check_body_read_authority` returns `False` on an
absent `submitter_domain_ref`.

> ***A CLAIM THAT WAS TRUE WHEN WRITTEN IS NOT THEREBY TRUE. PROSE ABOUT
> ANOTHER MODULE DATES, AND ONLY A RE-READ SAYS WHEN.*** **Stage 1 does not inherit that**: here,
absence on the REQUEST refuses, and a row with no discriminator is never
silently included in a `per_tenant` answer.
"""

from __future__ import annotations

from boundry_connector.refusal import Refusal, shown as _shown

import pathlib
import sys
from typing import Any

__all__ = ["ScopeRefused", "GLOBAL", "PER_TENANT",
           "apply_scope", "canon_filter_source"]

_PROGRAMME = pathlib.Path(__file__).resolve().parents[2]
_KERNEL = _PROGRAMME.parent / "A-Claude-Kernel" / "BoundryCompiler"
if str(_KERNEL) not in sys.path:
    sys.path.insert(0, str(_KERNEL))

# The one enforcement site, imported. `K-3`: this is a definition-only import.
from compiler.stages.tenant_scope import _apply_tenant_scope     # noqa: E402
from compiler.types.errors import TenantContextRequired          # noqa: E402

GLOBAL = "global"
PER_TENANT = "per_tenant"


class ScopeRefused(Refusal):
    """The connector's own refusal. Carries the cause, never a default answer.

    ⚠ Deliberately NOT `TenantContextRequired`. The `v0.2 IN FORCE` limits
    record that the absent-scope refusal SHARES its exception type with
    `TenantContextRequired`, "the two causes legible only by detail — recorded
    beside the `BV-025` family for a future round". The connector is a new
    read path and does not have to inherit an ambiguity that is already on the
    record as owed; a caller here can tell the connector's refusal from the
    engine's by TYPE and not by reading a string.
    """

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


def canon_filter_source() -> str:
    """Where the enforcement actually lives, for `chain_status` to name.

    A figure names the construction that produced it; an enforcement names the
    file that performs it.

    ⚠ **RELATIVE TO THE BUNDLE ROOT, NEVER ABSOLUTE.** This returned
    `inspect.getsourcefile(...)`'s absolute path, so `chain_status` handed any
    caller — under either scope label — a path of the SERVING HOST, naming its
    user account and its directory layout.

    > ***A FIGURE NAMES ITS INSTRUMENT, NOT ITS HOST. AN ABSOLUTE PATH IN A
    > RESPONSE IS CONFIGURATION LEAKING THROUGH AN ANSWER.***

    `EXP-006` is the same rule one surface over: *a path is a name*, which is
    why the declared-roots refusal does not echo the path either. The kernel
    root is the bundle root here, so the figure reads
    `compiler/stages/tenant_scope.py:_apply_tenant_scope`.

    ⚠ **AND THE FALLBACKS ALSO DO NOT LEAK.** If the filter is ever imported
    from outside the kernel tree, `relative_to` raises — so the anchor is
    searched for by name, and if even that fails the figure says it cannot be
    rendered rather than returning what it has. *A figure that cannot be
    rendered safely is reported as not rendered, never rendered unsafely.*
    """
    import inspect

    src = inspect.getsourcefile(_apply_tenant_scope)
    if src is None:                                     # pragma: no cover
        return "(instrument path unavailable):_apply_tenant_scope"
    path = pathlib.Path(src).resolve()
    try:
        rel = path.relative_to(_KERNEL)
    except ValueError:
        parts = path.parts
        if "compiler" in parts:
            rel = pathlib.Path(*parts[parts.index("compiler"):])
        else:                                           # pragma: no cover
            return "(instrument outside the bundle root):_apply_tenant_scope"
    return f"{rel.as_posix()}:_apply_tenant_scope"


def apply_scope(rows: list[Any], *, tenant_scope: str | None,
                tenant_context: str | None = None) -> list[Any]:
    """Scope `rows` (anything carrying `.submitter_domain_ref`).

    Absence of `tenant_scope` REFUSES. `global` is a DECLARED scope and passes
    through unfiltered — the declaration is its identity, which is a
    distinction and not a loophole. `per_tenant` without a context refuses.
    """
    if tenant_scope is None:
        raise ScopeRefused(
            "connector-tenant-scope-absent",
            "every envelope-returning tool must declare tenant_scope "
            "('global' or 'per_tenant'); absence of identity is not "
            "omniscience (this is the connector's own read path)",
        )
    if tenant_scope not in (GLOBAL, PER_TENANT):
        raise ScopeRefused(
            "connector-tenant-scope-unknown",
            f"tenant_scope must be {GLOBAL!r} or {PER_TENANT!r}; "
            f"got {_shown(tenant_scope)}",
        )
    selector: dict[str, Any] = {"tenant_scope": tenant_scope}
    if tenant_context is not None:
        selector["tenant_context"] = tenant_context
    try:
        return _apply_tenant_scope(rows, selector)
    except TenantContextRequired as exc:
        # The engine's refusal, relayed with its own cause named rather than
        # translated into ours. `BV-024`: the refusing party says why.
        raise ScopeRefused(
            "engine-tenant-context-required",
            f"{getattr(exc, 'detail', str(exc))} "
            "[raised by compiler.stages.tenant_scope._apply_tenant_scope]",
        ) from None
