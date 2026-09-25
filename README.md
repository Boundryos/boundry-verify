> **This repository holds the release, not the source tree.** Download `boundry-verify-0.3.0-stage1.mcpb` from [Releases](https://github.com/Boundryos/boundry-verify/releases) and open it with Claude Desktop. The `.mcpb` is a zip file: the files and the check command described below are inside it. Documentation: https://verify.boundry.tech/ · Privacy: https://verify.boundry.tech/privacy/ · Contact: verify@boundry.tech

# Boundry Verify — a local, read-only connector over sealed records

## ⚠ Do not take any of this on trust — run the checks

    python3 -I -B -m unittest discover -s server/boundry_connector -t server

**74 checks, in this package, with nothing installed.** They use only the
standard library: no test framework to fetch, no network, no configuration.
Every *Held by* line below names a check in that run.

## It needs Python 3.12 or newer, and it will say so

`manifest.json` declares `compatibility.runtimes.python: ">=3.12"`, and the
package enforces it. Both entry points and the check runner call the floor guard
as their FIRST act and refuse below it, before doing any work, naming the floor
and the version they found:

    INTERPRETER-BELOW-DECLARED-FLOOR: this package declares Python >= 3.12
    and is running under 3.9 … REFUSING before doing any work.

The floor is declared in one place, `boundry_verify/floor.py`, as a pair of
integers. The manifest's `compatibility` spec and its stated requirement are both
DERIVED from that pair at generation time, so the manifest and the guard cannot
disagree about the number.

**A refusal is a verdict you can act on. A green run on the wrong interpreter is
not.** The Python that ships with macOS is older than the floor. Install a
current one from python.org or your package manager.

**Measured on four interpreters, with nothing installed for any of them:**

| interpreter | third-party packages | result |
|---|---|---|
| macOS system Python 3.9.6 | none | **REFUSED before any work**, exit 2 |
| Python 3.12.12 | none | **74 run, 0 failures, 0 skipped** |
| Python 3.13.7 | none | **74 run, 0 failures, 0 skipped** |
| Python 3.13.7 | `pydantic` | **74 run, 0 failures, 0 skipped** |

⚠ **BELOW THE FLOOR THERE IS NO RUN TO SKIP ANYTHING IN.** 3.9.6 does not skip;
it refuses. Below the floor 32 of this package's 44 modules cannot be imported,
and a suite reporting `OK` with quiet skips would tell you the opposite of what
happened.

21 of the 74 checks read the shipped source rather than importing it, and
need nothing installed; the other 53 import the package or drive the running
server. **The verifier is pure standard library.**

Ten consecutive runs on each interpreter gave the same last line every time.
Nothing here depends on ordering, the clock, the network, or the filesystem
outside this directory.

⚠ Running the checks does not alter this package. Its tree digest is the same
before and after; the launch command carries `-B` so no bytecode is written.

## What it is

It is an MCP server that runs **on your own machine** and reads sealed records
from folders **you name**. It contacts nothing, writes nothing, attaches to no
database, subscribes to no emitter, and cannot sign.
*Held by:* the checks `it_opens_no_socket_and_contacts_no_endpoint`,
`it_attaches_to_no_database`, `it_cannot_sign`,
`it_neither_writes_nor_subscribes` and `it_imports_no_emitter_and_no_mcp_package`
in the run above. Each reads this package's own imports by AST, and each
carries a planted control — a synthetic import that the same check must reject —
so a check cannot report green by measuring nothing.

## What it does

Seven tools, all read-only, and **each one says so in its own declaration**:
every tool carries `readOnlyHint: true`, `destructiveHint: false`,
`idempotentHint: true`, `openWorldHint: false`, and a title.

**Every tool takes `corpus_dir`, and it takes a NAME.** `corpus_dir: the label of a declared
folder — with none configured, `kit` (the evaluation kit) or `demo` (the demonstration records) —
or its full path.` The two packaged folders answer to those two words with nothing configured, so
the first call works before anything is set up; a folder you declare as `label=path` answers to
its label too, and a folder declared as a bare path answers to its path.
*Held by:* `the_two_packaged_roots_answer_to_their_LABELS_over_a_REAL_pipe`, which asks for both
of them by name over a real pipe with nothing configured;
`a_label_that_is_not_declared_is_REFUSED_and_no_path_is_shown`; and
`the_wording_the_model_is_given_is_the_wording_that_RESOLVES`, which requires this sentence, the
tool schemas and the server's instructions to be the same sentence, built from the one place the
two labels are declared.

| tool | what it answers |
|---|---|
| `verify_record` | a record in, the verifier's verdict out |
| `get_envelope` | one envelope, tenant-scoped |
| `query_envelopes` | envelopes in scope |
| `chain_status` | head, era, manifest seq, sweep figures, instrument named |
| `explain_record` | a record's provenance, rendered from artefacts; for a kernel export, its lineage link by link |
| `check_plan_identity` | a sealed plan's id recomputed from its six inputs, and its seal checked |
| `compare_runs` | two runs, each against its own record, then field by field: EQUIVALENT, DIVERGENT or UNREACHABLE |

*Held by:* `boundry_connector.TOOL_NAMES`, a seven-member tuple in this package;
the checks `every_tool_declares_a_title_and_the_four_hints` and
`the_annotations_reach_the_client_over_a_real_pipe`, which reads them back over
a real pipe rather than out of the source.

⚠ The tool descriptions in `manifest.json` are **derived** from the same
declaration the server answers with, never typed. The table above is prose for a
reader; the manifest is the machine-readable copy and it has one source.

**There is no write tool, and no disabled one.** If submission is ever built it
arrives as a new tool under its own ruling — a wall now, a door later, never a
lock a flag opens.
*Held by:* `there_is_no_write_tool_and_no_disabled_one`,
`the_tool_surface_is_exactly_seven_and_they_are_the_declared_seven`,
`no_tool_name_carries_a_write_shaped_verb` and, over a real pipe,
`the_sixth_name_is_absent_over_the_wire_too`.

## The evaluation kit

`kit_evidence/`, beside the demonstration corpus, holds evidence from real governed runs of
the Boundry Substrate: one CALCULATION, the smallest real TRANSFORMATION chain, and one
refused request, each run independently on two platforms — macOS arm64 and Linux aarch64 —
in fresh processes against fresh roots. Each run is a kernel export: the record's own signed
payload bytes, its form hashes, the bodies it names, and the intent as submitted. Three
tampered copies of one export sit beside them, and one verifying key. The inputs are
synthetic.

**E1 · A plan's identity is a deterministic function of its inputs:** versions, intent
hash, input hashes and pins. It does not identify the plan body. Two different plan bodies
were measured carrying the same id — a changed budget, the same input under another
artefact id, and two registries publishing one pinned agent differently; the body is
identified by the seal's content hash, and the answer says so.
*Held by:* `E1_each_sealed_plan_recomputes_its_id_and_its_seal` and
`E1_the_answer_says_what_the_id_identifies`, through `check_plan_identity`, which
recomputes with `kit.identity` in this package.

**E2 · The same governed request, run in fresh processes on two different platforms (macOS
arm64 and Linux aarch64), produced byte-identical outputs, plan body, result and payload
signatures.** Only wall-clock stamps, and hashes taken over them, differ. The two runs were
made by different people on different machines.
*Held by:* `E2_the_same_request_on_each_platform_is_EQUIVALENT`, through `compare_runs`,
which names each differing field and marks the expected ones with the reason from
`kit.EXPECTED_TO_DIFFER`.

**E3 · Tampering after the fact is detected:** a changed output byte, a forged hash, or a
lost output. This is hash comparison, not re-execution, and it is not offered as E2.
*Held by:* `E3_each_tampered_copy_is_caught_for_what_was_done_to_it`.

**E4 · The substrate refuses an inadmissible request, and the refusal is itself a signed
record with its reason.**
*Held by:* `E4_the_refusal_is_a_signed_record_with_its_reason`, through `explain_record`.

**E5 · No model is loaded or called in governed operation.** The kit ships the result of
that check and the sha256 of the instruments that produced it — not their source. This item
is therefore a result, not a check you can re-run here.
*Held by:* `E5_the_conduct_line_result_ships_with_its_instruments_digests`, reading
`CONDUCT_LINE_RESULT.json`.

**E6 · Each link from intent to output is hash-bound and recomputes offline.** Each run
ships with its submitted intent beside it, because the record carries the intent's hash and
not the intent.
*Held by:* `E6_each_run_walks_link_by_link`, through `explain_record`; its control
`honest_control_a_CHANGED_intent_breaks_the_first_link`; and
`the_kit_tools_answer_over_a_REAL_pipe`.

**The kit ships verifying keys and nothing that signs.** A signing key and an HMAC secret
are not in this package; an evaluator verifies and does not re-sign.
*Held by:* `the_package_carries_verifying_keys_and_no_secret`.

⚠ Each export records the digest of the generator that MADE it. That is the generator
which ran, and it is left as it was: the evidence was not re-made to match a later one.

## What it refuses

A read with no declared tenant scope is **refused, never widened**.
*Held by:* `scope.apply_scope` in this package, and the check
`a_read_with_no_declared_scope_REFUSES_and_is_not_widened`. The substrate's own
absent-scope refusal sits behind it in `compiler.stages.tenant_scope`, which
ships here too.

A folder you have not declared is refused with **`corpus-root-not-declared`**.
*Held by:* `corpus.Corpus._check_reach` via `corpus._within_a_declared_root`, and the
check `a_folder_you_have_not_declared_is_refused_for_THAT`.

The four states of a root, and the two codes, answer different questions:

| you named | on disk | code |
|---|---|---|
| a declared root | present | *(no refusal)* |
| a declared root | absent | `corpus-root-absent` |
| an undeclared folder | present | `corpus-root-not-declared` |
| an undeclared folder | absent | `corpus-root-not-declared` |

The declared-root check runs FIRST, so an undeclared folder is refused for **not
being declared** whether or not it exists — the reason you are given is the
reason that applies, not the first fault encountered.
*Held by:* `a_folder_you_have_not_declared_is_refused_for_THAT`,
`a_declared_root_that_is_absent_is_refused_for_ABSENCE` and
`the_two_refusals_are_told_APART`.

Unset `BOUNDRY_CONNECTOR_ROOTS` means the two packaged synthetic roots — the
demonstration corpus and the evaluation kit's evidence — **and nothing else**. The
safe default is the narrow one.
*Held by:* `corpus.allowed_roots` in this package — read it and see that unset
means those two roots and nothing else — and the check
`UNSET_roots_mean_the_two_packaged_roots_and_nothing_else`.

### A root holds records, kernel exports, and three files named one by one

Each JSON file in a root is a record, a kernel export, or one of
`key_directory.json`, `EXPORT_MANIFEST.json` and `CONDUCT_LINE_RESULT.json`. A file
that is none of them — a list, a scalar, an object with no `record_id` — refuses
the root as `corpus-entry-not-a-record`, naming the root's label and the file's
shape. It is not read around.
*Held by:* `a_NON_RECORD_json_file_is_REFUSED_by_name_by_every_tool`, which plants
each shape and calls each of the seven tools; its control
`honest_control_the_same_root_WITHOUT_the_file_is_READ`; and, over a real pipe,
`a_NON_RECORD_file_is_refused_over_a_REAL_pipe`.

### A kernel export whose contents do not decode is refused by name

A file that carries the kernel-export marker and its declared fields, but whose contents do not
decode — a hex field that is not hex, or a payload that is not a UTF-8 JSON object — refuses the
root as `corpus-export-undecodable`, naming the root's label and no path.
*Held by:* `an_UNDECODABLE_export_is_REFUSED_by_name_by_every_tool`, which plants three such
contents and calls each of the seven tools; its control
`honest_control_the_same_root_with_the_INTACT_export_is_READ`; and, over a real pipe,
`an_UNDECODABLE_export_is_refused_over_a_REAL_pipe`.

### A link cannot widen a declared root

Every file the connector opens must resolve — link by link, to its final
target — **inside** the declared root it was found in. If it does not, it is not
opened, and the refusal is **`corpus-entry-outside-root`**, naming the root's
label and no path. This holds for records, for `key_directory.json` (so a planted
link cannot choose the keys a signature is checked against) and for
`EXPORT_MANIFEST.json` (so a planted link cannot forge the client comparison).

| an entry in a declared root that is… | it is… | code |
|---|---|---|
| a regular file | read | *(no refusal)* |
| a link whose final target is **inside** the root | read — it reads nothing the root does not hold | *(no refusal)* |
| a link (file, directory, relative, or a chain) whose final target is **outside** | not opened | `corpus-entry-outside-root` |
| a file with **more than one name** (a hard link) | not read — a hard link has no target to check | `corpus-entry-hard-linked` |
| not a regular file | not read | `corpus-entry-not-a-file` |
| unreadable | not read | `corpus-entry-unreadable` |

⚠ A hard link is refused whether or not it is legitimate: the check cannot see
where it points, and a refusal it can justify is better than a read it cannot.

*Held by:* `a_FILE_link_to_outside_the_root_is_REFUSED_for_where_it_points` and its
control `honest_control_the_SAME_record_COPIED_inside_the_root_is_read`;
`a_DIRECTORY_link_to_outside_is_REFUSED_both_as_an_entry_and_as_a_root`;
`a_link_that_resolves_INSIDE_the_root_is_ADMITTED`;
`a_RELATIVE_link_and_a_CHAIN_of_links_are_followed_to_the_END`;
`a_HARD_link_is_REFUSED_because_realpath_cannot_see_it`;
`the_VERIFICATION_KEYS_and_the_EXPORT_MANIFEST_cannot_come_from_outside`; and, over
the shipped launch command, `GOVs_exact_attack_over_a_REAL_pipe_is_now_REFUSED`.

### A refusal never renders a path

Not the path you named, not one a record or an export carries, and not one the
operating system puts in an error. In a practice's folder structure a client's
path IS their name, so the connector renders a declared root's **label**. A value
you supplied — a record id, a tool name, an argument name, a scope — is shown
only if it is a plain identifier (letters, digits, `.`, `_`, `-`); anything else
is withheld and the refusal says so.
*Held by:* the check `a_refusal_never_echoes_the_path_you_named`, which
plants a path into **every** refusal the package can raise, and
`every_refusal_code_the_package_can_raise_IS_driven_here`, which derives that set
from the source so a refusal added later cannot escape it; with the control
`honest_control_an_ECHOING_refusal_IS_caught`.

### One name, one version

On `initialize` the server announces **`boundry-verify`**, titled **Boundry Verify**,
version **`0.3.0-stage1`** — the same name, display name and version `manifest.json`
carries. All three come from one declaration in `boundry_connector/__init__.py`, and
the version is built from the package's stage, so the handshake cannot claim a stage
it is not running. **`stage1` means this stage reads and verifies**: there is no write
tool, and adding one would be a different build under its own ruling.
*Held by:* `serverInfo_over_a_REAL_pipe_IS_the_manifests_name_and_version`, with the
control `honest_control_a_manifest_that_DISAGREES_is_seen_to`; and
`the_old_public_identity_appears_only_as_history`, with its control
`honest_control_a_document_carrying_the_old_identity_IS_caught`.

<!-- HISTORY:START -->
History: earlier pre-release builds of this package announced
`boundry-private-connector` `0.1.0-stage1`.
<!-- HISTORY:END -->

## What it depends on

**Nothing outside the standard library**, stated as a measurement rather than a
boast. The chain is:

    server.py -> tools.py -> scope.py -> compiler.stages.tenant_scope
      -> compiler.types.errors   (standard library only)

The bundle format requires that every dependency be bundled — in `server/lib` or
a `server/venv`. **There are none to bundle:** importing this package and reading
what that pulled in measures ZERO third-party distributions. The substrate the
records come from declares seven of its own (`fastapi`, `uvicorn[standard]`,
`pydantic`, `cryptography`, `orjson`, `aiosqlite`, `psycopg`); this package
reaches none of them. A dependency a project DECLARES is not a dependency a
package IMPORTS, and only the second has to be bundled.

*Held by:* `the_chain_this_package_states_is_the_chain_it_has` and
`the_kernel_hop_leaves_this_package_through_scope_only`, which read the imports
in the shipped source. The chain is measured, not recalled.

## The honest sentence

> **one key signs everything and you hold it; the determinism shown is for the
> governed road, on the workloads in the kit, across the platforms named.**

That is the ceiling. Nothing in these documents climbs above it.

<!-- WORDS-NOT-USED:START -->
This document does not say *tamper-proof*, *immutable*, *guaranteed*, or
*we cannot read your data* — those are not this system's claims.
<!-- WORDS-NOT-USED:END -->
*Held by:* the check `no_document_makes_a_claim_the_code_does_not_hold`, which
reads this document with the block above removed, so a denial is not mistaken
for a claim.

## Privacy policy, and who to contact

The hosted privacy policy's address is the manifest's `privacy_policies` entry,
and the author, contact address and documentation address sit beside it — each
written from one declaration. What the policy says about this package is
`PRIVACY.md`, which ships here. Who to write to is `CONTACT.md`.
*Held by:* `the_manifests_contact_fields_are_real_and_agree_with_the_documents`,
which reads each of those manifest fields and requires a real address rather than
a placeholder.

## Licence

Free to use; not open source. See `LICENSE.txt`, which ships beside this file. You may install and
use this package, unmodified, including to evaluate it and to verify records with it; you may not
modify, distribute or publish it without written permission. `manifest.json` names the same licence
in its `license` field.
*Held by:* `every_document_is_present`, which requires `LICENSE.txt` to be in the package you were
handed, beside this document.

## What it does not do

It does not make your conversation private. See `PRIVACY.md` — that is the part
most likely to be misread, and it is not a detail.

