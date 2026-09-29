---
name: boundry-verify
description: Use when the user asks to check Boundry records or to try the Boundry Verify evaluation kit, for example comparing two runs or explaining a record's lineage. Call the Boundry Verify tools on the packaged `kit` or `demo` folder and report the connector's answer as it returns it.
---

# Boundry Verify

## When this applies

- The user asks to check a Boundry record, compare two Boundry runs, or explain where a record came from.
- The user asks to try the evaluation kit, or names a run in it: `calculation-m2`,
  `calculation-linux-aarch64`, `calculation-m2--forged-hash` or `transformation-m2`.

## How to call the tools

- Pass `corpus_dir` as `kit` (the evaluation kit) or `demo` (the demonstration records). The plugin
  reads these two packaged folders and nothing else. If the user wants their own folders read,
  tell them to install the `.mcpb` from the repository's Releases instead.
- Pass `tenant_scope` as `global` unless the user names another scope. A read with no scope is
  refused.
- The three prompts below name runs in `kit`. `demo` holds different records (`rec-a-0001` and the
  others), so do not suggest re-running these prompts on `demo`; to explore it, call
  `query_envelopes` on `demo` with `tenant_scope` `global` first.

## The three prompts in the README, and what each should return

1. "Use Boundry Verify to compare runs calculation-m2 and calculation-linux-aarch64 in the kit,
   global scope." Call `compare_runs`. Expect **EQUIVALENT** for both runs. The fields that differ
   are all marked as expected, each with its reason: `transition_timestamp_us`,
   `envelope_form_hash`, `environment`, `platform_tag` and `run_id`.
2. "Compare calculation-m2 with calculation-m2--forged-hash in the kit, global scope." Call
   `compare_runs`. Expect **calculation-m2 EQUIVALENT** to its own record and
   **calculation-m2--forged-hash DIVERGENT**: its signature fails at envelope 9
   (`envelope-signature-fails`). It differs in `payload_canonical_bytes` and `bodies`, and carries
   `tampering` and `tampered_from`; the connector marks all four as findings.
3. "Explain record transformation-m2 in the kit, global scope." Call `explain_record`. Expect the
   export's lineage, link by link: the record's order, the submitted intent, the plan carrying that
   intent, the input hashes, the sealed plan, the execution naming the sealed plan, the output
   hashes, and the closure counts.

## How to report the answer

- Give the verdict the connector returned, in its own words, and the fields it names.
- Give its "not established" lines as returned. Do not add to them, drop any, or soften them.
- If the connector refuses, give the refusal code and its detail as returned. Do not retry with
  another folder or scope unless the user asks.
- Do not go beyond the reply. `compare_runs` is hash comparison, not re-execution, and the records
  in `kit` and `demo` are synthetic.
