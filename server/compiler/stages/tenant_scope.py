"""BOUNDRYDB-3B-TENANT — the ONE tenant-isolation rule, in its own module.

The rule below is canon's single tenant-scope filter. It was lifted BYTE FOR
BYTE out of ``compiler/stages/query_execution.py``; not one character of the
rule changed, and this module adds no second rule. The move exists so the rule
can be READ by a verifier that has no model layer: ``query_execution`` reaches
the whole QUERY execution path (substrate, the envelope emitter, the Phase-2
materialiser, pydantic models), and a reader that only wants to answer "what
does canon say about tenant scope?" had to drag all of it in.

What this module needs at RUNTIME is one exception class from
``compiler.types.errors``, which imports nothing but the standard library.
``AuditEnvelope`` appears in annotations only, so it is imported under
``TYPE_CHECKING`` and never loaded: with ``from __future__ import annotations``
the annotations are strings and are never evaluated.

⚠ The call site is unchanged. ``execute_query`` still calls this function at the
same point in the same order; the QUERY path's behaviour is identical.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compiler.types.errors import TenantContextRequired

if TYPE_CHECKING:  # pragma: no cover - typing only
    from compiler.types.envelope import AuditEnvelope


def _apply_tenant_scope(
    envelopes: list[AuditEnvelope], selector: dict[str, Any]
) -> list[AuditEnvelope]:
    """Tenant isolation (BOUNDRYDB-3B). A ``per_tenant`` selector requires a
    ``tenant_context`` and returns only envelopes whose ``submitter_domain_ref``
    matches it — cross-tenant reads are structurally impossible, not policy. An
    explicit ``global`` scope is unfiltered. The substrate filters by a neutral
    field; it does not know what a "tenant" means.

    ⚠,
    TEN-002(a): **an ABSENT ``tenant_scope`` now REFUSES.** It used to default to
    ``global`` and return the union — a selector that had declared nothing was
    silently omniscient, which is the one reader that could drop the sealed
    discriminator without forging anything. `global` is not that reader: it is a
    SCHEMA-DECLARED scope, and the schema's declaration is its identity. Absence
    declares nothing, and absence of identity is not omniscience.

    Measured before the change: exactly 6 invocations across 2 kernel test
    functions relied on the default, and both were determinism tests that had no
    view about tenancy. They now say ``global`` in as many words.
    """
    if "tenant_scope" not in selector:
        raise TenantContextRequired(
            detail="a QUERY selector must declare tenant_scope; absence of "
                   "identity is not omniscience",
            subject={"tenant_scope": None},
        )
    tenant_scope = selector["tenant_scope"]
    if tenant_scope != "per_tenant":
        return envelopes
    tenant_context = selector.get("tenant_context")
    if not tenant_context:
        raise TenantContextRequired(
            detail="a QUERY over a per_tenant schema requires a tenant_context",
            subject={"tenant_scope": "per_tenant"},
        )
    return [e for e in envelopes if e.submitter_domain_ref == tenant_context]
