"""The evaluation kit's checks over a kernel EXPORT (design v0.2).

An export is what `CONNECTOR/packaging/make_kit_evidence.py` writes from a real governed run: the
record's own rows (signed payload bytes, form hashes, seal signature), the bodies it names, and the
SUBMITTED intent. Every check here recomputes from those bytes with the programme's INDEPENDENT
verifier (`boundry_verify`: CF-ENC-001, RFC 8032 Ed25519, the v3 envelope form). The kernel is not
imported.

⚠ **MEASURED BEFORE E1 WAS WORDED.** `micro_contract_id` is a deterministic function of six
inputs — compiler and substrate versions, the intent's hash, the input hashes, and the two pin maps.
Two different sealed bodies carried the SAME id in each of three cases (a changed budget, the same
input bytes under another artefact id, and two registries publishing one pinned agent version with
different output contracts). The id identifies those six inputs; the plan BODY is identified by the
seal's `content_hash`, and `identity()` reports both.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from boundry_verify.canonical_form import canonical_bytes
from boundry_verify.ed25519 import verify as ed25519_verify
from boundry_verify.envelope_form_v3 import envelope_leaf_hash_v3

__all__ = ["NS_MICRO_CONTRACT", "EXPECTED_TO_DIFFER", "identity", "integrity", "compare", "lineage",
           "domain_of", "F87_STATEMENT"]

#: The namespace the id derivation uses (`uuid5`), as the kernel declares it for Compiler 1.0.x.
NS_MICRO_CONTRACT = "5b6d2c3e-4f70-5182-9b0a-5b6d2c3e4f70"

F87_STATEMENT = (
    "micro_contract_id is a deterministic function of six inputs: compiler_version, "
    "substrate_version, intent_content_hash, the input hashes in order, and the contract and agent "
    "pin maps. Measured (F-87): two different plan bodies can carry the same id. The plan body is "
    "identified by the seal's content_hash.")

#: Between two independent runs of ONE governed request, these fields are expected to differ, each
#: for the reason given. A difference in a field outside this map is a finding.
EXPECTED_TO_DIFFER: dict[str, str] = {
    "transition_timestamp_us": "the wall clock at each envelope's write",
    "envelope_form_hash": "the v3 form seals transition_timestamp_us",
    "run_id": "the run's own label",
    "platform_tag": "which platform ran it",
    "environment": "the interpreter, operating system, machine and packages the run was made with",
}

_SHA = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731


def _payloads(export: dict) -> list[dict]:
    return [json.loads(bytes.fromhex(e["payload_canonical_bytes"])) for e in export["envelopes"]]


def _by_kind(export: dict, kind: str) -> list[tuple[dict, dict]]:
    return [(e, p) for e, p in zip(export["envelopes"], _payloads(export)) if e["envelope_kind"] == kind]


def domain_of(export: dict) -> str | None:
    """The tenant a run was submitted under, as its record states it — what the scope rule reads."""
    return export["envelopes"][0].get("submitter_domain_ref") if export.get("envelopes") else None


def _check(name: str, holds: bool, binds_by: str, detail: str = "") -> dict:
    return {"check": name, "holds": bool(holds), "binds_by": binds_by, "detail": detail}


def identity(export: dict, key_hex: str) -> dict | None:
    """E1 over the sealed plan in `export`; `None` when the run sealed no plan (it was refused)."""
    sealed = _by_kind(export, "compiler.micro_contract_sealed")
    if not sealed:
        return None
    env, pay = sealed[0]
    body_hex = export["bodies"].get(pay["content_hash"])
    body = bytes.fromhex(body_hex) if body_hex is not None else None
    plan = json.loads(body) if body is not None else {}
    fields = {
        "compiler_version": plan.get("compiler_version"),
        "substrate_version": plan.get("substrate_version"),
        "intent_content_hash": plan.get("intent_content_hash"),
        "input_hashes": [i.get("artefact_hash") for i in plan.get("inputs", [])],
        "pinned_contracts": plan.get("pinned_contract_versions"),
        "pinned_agents": plan.get("pinned_agent_versions"),
    }
    recomputed = str(uuid.uuid5(uuid.UUID(NS_MICRO_CONTRACT), canonical_bytes(fields).decode("utf-8"))) \
        if body is not None else None
    checks = [
        _check("the sealed body is present", body is not None, "micro_contract_sealed.content_hash"),
        _check("the body hashes to the sealed content_hash", body is not None and _SHA(body) == pay["content_hash"],
               "sha256(body) = micro_contract_sealed.content_hash", pay["content_hash"]),
        _check("the seal verifies over the body", body is not None and env.get("seal_signature") is not None
               and ed25519_verify(bytes.fromhex(key_hex), body, bytes.fromhex(env["seal_signature"])),
               "Ed25519 seal_signature over the body, under the export's signing key id"),
        _check("the id recomputes from the six inputs", recomputed == plan.get("micro_contract_id"),
               "uuid5(namespace, canonical(six fields))", str(recomputed)),
        _check("the sealed envelope names that id", recomputed == pay.get("micro_contract_id"),
               "micro_contract_sealed.micro_contract_id"),
    ]
    return {"micro_contract_id": pay.get("micro_contract_id"), "content_hash": pay["content_hash"],
            "fields_used": fields, "checks": checks, "holds": all(c["holds"] for c in checks)}


def integrity(export: dict, key_hex: str) -> dict:
    """The export against ITS OWN record: EQUIVALENT, DIVERGENT or UNREACHABLE, with the reason."""
    envs, pays = export["envelopes"], _payloads(export)
    key = bytes.fromhex(key_hex)
    prev = None
    for e, p in zip(envs, pays):
        pb = bytes.fromhex(e["payload_canonical_bytes"])
        if not ed25519_verify(key, pb, bytes.fromhex(e["signature_bytes"])):
            return {"verdict": "DIVERGENT", "reason": "envelope-signature-fails", "position": e["position"]}
        form = envelope_leaf_hash_v3(envelope_kind=e["envelope_kind"], payload_hash=_SHA(pb),
                                     position=e["position"], prev_envelope_hash=prev,
                                     transition_timestamp_us=e["transition_timestamp_us"],
                                     submitter_principal_id=e["submitter_principal_id"],
                                     submitter_domain_ref=e["submitter_domain_ref"])
        if form != e["envelope_form_hash"]:
            return {"verdict": "DIVERGENT", "reason": "envelope-form-hash-fails", "position": e["position"]}
        prev = e["envelope_form_hash"]
    if not envs or envs[-1]["envelope_kind"] != "compiler.request_closed":
        return {"verdict": "UNREACHABLE", "reason": "request-not-closed-on-the-record"}
    closing = pays[-1]
    outputs = [p for e, p in zip(envs, pays) if e["envelope_kind"] == "compiler.output_materialised"]
    if closing.get("chain_length") != len(envs) - 1 or closing.get("output_count") != len(outputs):
        return {"verdict": "DIVERGENT", "reason": "closure-counts-disagree"}
    for p in outputs:
        body = export["bodies"].get(p["content_hash"])
        if body is None:
            return {"verdict": "UNREACHABLE", "reason": "output-lost", "artefact_id": p["artefact_id"]}
        actual = _SHA(bytes.fromhex(body))
        if actual != p["content_hash"]:
            return {"verdict": "DIVERGENT", "reason": "output-hash-mismatch", "artefact_id": p["artefact_id"],
                    "recorded": p["content_hash"], "bytes_hash_to": actual}
    return {"verdict": "EQUIVALENT", "reason": None, "envelopes": len(envs), "outputs": len(outputs),
            "outcome_on_record": closing.get("outcome")}


def _leaves(a: Any, b: Any, path: str = "") -> list[str]:
    if isinstance(a, dict) and isinstance(b, dict):
        return [x for k in sorted(set(a) | set(b))
                for x in _leaves(a.get(k, "<absent>"), b.get(k, "<absent>"), f"{path}.{k}" if path else k)]
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return [x for i, (u, v) in enumerate(zip(a, b)) for x in _leaves(u, v, f"{path}[{i}]")]
    return [] if a == b else [path]


def compare(a: dict, b: dict, key_hex: str) -> dict:
    """E2/E3: two exports, each against its own record, then field by field."""
    ia, ib = integrity(a, key_hex), integrity(b, key_hex)
    counted: dict[str, int] = {}
    for path in _leaves(a, b):
        field = path.split("]")[-1].lstrip(".") if "]" in path else path
        top = field.split(".")[0]
        name = top if top in EXPECTED_TO_DIFFER or top == "bodies" else field
        counted[name] = counted.get(name, 0) + 1
    differences = [{"field": f, "leaves": n, "expected": f in EXPECTED_TO_DIFFER,
                    "why": EXPECTED_TO_DIFFER.get(f, "outside the expected set: a finding")}
                   for f, n in sorted(counted.items())]
    if "UNREACHABLE" in (ia["verdict"], ib["verdict"]):
        verdict = "UNREACHABLE"
    elif "DIVERGENT" in (ia["verdict"], ib["verdict"]) or any(not d["expected"] for d in differences):
        verdict = "DIVERGENT"
    else:
        verdict = "EQUIVALENT"
    return {"verdict": verdict, "run_a": ia, "run_b": ib, "differences": differences}


def lineage(export: dict, key_hex: str) -> list[dict]:
    """E6 (and E4's refusal): each link from the submitted intent onward, and the field binding it."""
    envs, pays = export["envelopes"], _payloads(export)
    kinds = {e["envelope_kind"]: p for e, p in zip(envs, pays)}
    order = integrity(export, key_hex)
    links = [_check("the record's order: signatures and the form-hash chain",
                    order.get("reason") not in ("envelope-signature-fails", "envelope-form-hash-fails"),
                    "envelope_form_hash over kind, sha256(payload), position, the predecessor's form hash, "
                    "transition_timestamp_us, submitter", str(order.get("reason") or ""))]
    intent = export.get("submitted_intent") or {}
    ich = _SHA(canonical_bytes({k: intent.get(k) for k in ("intent_kind", "intent_version", "intent_payload")}))
    received, parsed = kinds.get("compiler.intent_received", {}), kinds.get("compiler.parse_succeeded", {})
    links.append(_check("the submitted intent is the one the record received and parsed",
                        ich == received.get("intent_content_hash") == parsed.get("intent_content_hash"),
                        "intent_content_hash (intent_received, parse_succeeded)", ich))
    failed = [(e, p) for e, p in zip(envs, pays) if e["envelope_kind"].endswith("_failed")]
    if failed:
        e, p = failed[0]
        closing = pays[-1]
        links.append(_check("the refusal is itself a signed record, with its reason",
                            order["verdict"] == "EQUIVALENT" and closing.get("outcome") == "rejected",
                            f"{e['envelope_kind']}.error_code, request_closed.outcome",
                            f"{p.get('error_code')} {p.get('error_name')}: {p.get('detail')}"))
        return links
    ident = identity(export, key_hex) or {"holds": False, "content_hash": None}
    plan_hex = export["bodies"].get(ident.get("content_hash") or "")
    plan = json.loads(bytes.fromhex(plan_hex)) if plan_hex else {}
    links.append(_check("the plan carries the intent the record parsed",
                        plan.get("intent_content_hash") == ich and plan.get("intent_id") == parsed.get("intent_id"),
                        "plan.intent_content_hash, plan.intent_id"))
    links.append(_check("each input's bytes hash to the plan's artefact_hash",
                        bool(plan.get("inputs")) and all(
                            i["artefact_hash"] in export["bodies"]
                            and _SHA(bytes.fromhex(export["bodies"][i["artefact_hash"]])) == i["artefact_hash"]
                            for i in plan.get("inputs", [])),
                        "plan.inputs[].artefact_hash = sha256(input bytes)"))
    links.append(_check("the sealed plan: body, seal and id", ident["holds"],
                        "micro_contract_sealed.content_hash, seal_signature, micro_contract_id"))
    started, done = kinds.get("compiler.execution_started", {}), kinds.get("compiler.execution_succeeded", {})
    links.append(_check("execution names the sealed plan",
                        started.get("micro_contract_id") == done.get("micro_contract_id") == plan.get("micro_contract_id"),
                        "execution_started / execution_succeeded .micro_contract_id",
                        "by id, which identifies the six inputs (F-87); the body is bound by the order and the seal"))
    outputs = [p for e, p in zip(envs, pays) if e["envelope_kind"] == "compiler.output_materialised"]
    links.append(_check("each output's bytes hash to the recorded content_hash, under the plan's id",
                        bool(outputs) and all(o["content_hash"] in export["bodies"]
                                              and _SHA(bytes.fromhex(export["bodies"][o["content_hash"]])) == o["content_hash"]
                                              and o["micro_contract_id"] == plan.get("micro_contract_id") for o in outputs),
                        "output_materialised.content_hash, .micro_contract_id"))
    closing = pays[-1] if pays else {}
    links.append(_check("the closure counts what the record holds",
                        closing.get("chain_length") == len(envs) - 1 and closing.get("output_count") == len(outputs),
                        "request_closed.chain_length, output_count"))
    return links
