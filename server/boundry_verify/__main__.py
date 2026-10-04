"""`python -m boundry_verify` — the documented entry point. `X5-1`.

## Why this file exists, and it is a guardrail finding rather than a convenience

**Until this pack `python -m boundry_verify` failed with *"a package and cannot
be directly executed"*, so consuming an external artefact meant calling the
Python API and DISCOVERING ITS SIGNATURES.** At `X-05` the exporter seat did
that with `inspect.signature`, `__doc__` and the public constants — and the
authorship guardrail held only because it reached for `inspect.signature` rather
than `inspect.getsource`.

> ***A guardrail that depends on which introspection function someone picks is
> not a guardrail. It is a coin that landed well.*** (on `X5-1`.)

**So: a stranger with a bundle and a key directory runs ONE COMMAND and never
reads a line of this package.** That is Phase 3's own exit sentence, and until
now it had never actually been true.

## ⚠ A REFUSAL MAY ECHO THE PATH **THIS** CALLER SUPPLIED — AND ONLY THIS ONE

A refusal from this command quotes the path it was handed, in full:

    refused: cannot read the bundle: [Errno 2] No such file or directory: '/…/b.cbor'

**That is correct HERE and it is a rule about WHO ASKED, not about paths.** This
command is run by a stranger, at a terminal, against paths that stranger typed.
Echoing one back discloses nothing they do not already hold, and it is what
makes a mistyped path diagnosable instead of merely refused.

> **RULED.** *The CLI may echo a path its own caller supplied. Any surface that
> takes a path from SOMEBODY ELSE — a service, a connector tool, anything
> answering a request on another party's behalf — must refuse WITHOUT echoing
> it.*

The connector already holds the other half, and holds it well:
`CONNECTOR/boundry_connector/tools.py` shares one refusal between
`get_envelope` and `explain_record` so that absence and out-of-scope cannot be
told apart, under its own sentence — *a refusal that names what it refused
discloses more than the tool that refused to show it.*

⚠ **So do not "harden" this file by stripping the path.** Doing that removes a
diagnostic from the one caller entitled to it and protects nobody. The obligation
belongs to whatever wraps this command for someone else, and it is written here
because that is where its author will look.

## ⚠ Everything provisioned stays provisioned. This CLI invents NOTHING.

`BV-004` and `BV-023` are not relaxed by putting a command in front of them.
**Every input this package refuses to default, this CLI also refuses to
default** — and it says which flag is missing rather than choosing:

- the **key directory** (`--key-directory`) has no default;
- the **witness trust list** (`--witness-trust-list`) has no default, and
  *omitting it is a different fact from an empty one* — no trust list means
  this verifier was never provisioned, an empty one means it anchors nobody,
  and the two produce different reason codes (`witness.WitnessTrustList`);
- the **bounds** (`--max-bundle-bytes`, `--der-max-*`) have no defaults in
  substance; the values printed below are this CLI's DECLARED choices, echoed
  on every run so a reader never has to guess what a verdict was measured
  under. **They are the operator's to set and they are always reported.**

## ⚠ What the exit code does and does not say

`ATTESTED` exits **0**. **Every other outcome exits 1 — including `UNATTESTED`,
which is not a failure of the record but an absence of evidence.** *A shell that
treats 1 as "the record is bad" has collapsed `ERR-P3-008`'s four outcomes back
into the boolean the whole vocabulary exists to prevent*, so the outcome is
printed as a word on its own line and `--json` emits it as a field. **Read the
word, never the code.**

## Usage

    python -m boundry_verify BUNDLE --key-directory DIR.json
                             [--witness-trust-list LIST.json]
                             [--json] [--max-bundle-bytes N]
                             [--der-max-bytes N] [--der-max-depth N]
                             [--der-max-elements N]

`DIR.json` is the key-directory specification's mapping. `LIST.json` maps
`witness_key_ref` to `{witness_kind, certificate_pem | public_key_pem |
key_material_hex, format}`. **Both travel out of band and neither comes from the
bundle** (`BV-012`, `BV-010`).
"""

from __future__ import annotations


# ⚠ **AFTER `from __future__`, WHICH MUST BE THE FIRST STATEMENT IN THE FILE.**
# The first cut of this patch put the guard above it and the module stopped
# parsing: `SyntaxError: from __future__ imports must occur at the beginning
# of the file`. "First act" is a rule about ORDER OF EXECUTION, and Python has
# one statement that outranks it. Caught by the proof run, which is what the
# proof is for.
#
# > ***"FIRST" IS A CLAIM ABOUT A LANGUAGE, NOT ABOUT AN INTENTION.***
# ⚠ **THE FLOOR, FIRST ACT.** `python -m boundry_verify` executes the package
# `__init__` first and is already guarded by it; this stands for the case where
# THIS file is the entry — run by path, as the manifest runs `server.py`.
# The check is idempotent and costs one JSON read.
from boundry_verify.interpreter_floor import assert_floor as _assert_floor  # noqa: E402

_assert_floor()

import argparse
import base64
import binascii
import json
import sys

from . import bundle as _bundle
from . import der, key_forms, token_rfc3161, witness
from .bundle_chain import RECOGNISED_PAYLOAD_FORM_TAGS, verify_bundle
from .keys import KeyDirectory, KeyDirectoryError
from .signature_form import THIS_ERA_SIGNATURE_FORM
from .verdict import ATTESTED

#: The witness kind this build ships a checker for. **The mapping is still the
#: OPERATOR's** (`BV-019`): this CLI registers exactly one kind, names it here,
#: and a bundle naming any other kind gets `token-kind-unverifiable` rather than
#: an error. *One real kind existing is exactly when it becomes tempting to make
#: it the default, and a default checker is a verifier deciding on the
#: operator's behalf which witnesses it will believe.*
RFC3161_KIND = "rfc3161"

#: ⚠⚠ **WHAT THIS COMMAND PROVISIONS, DERIVED AND NEVER TYPED**
#: (*any list that governs what is checked is
#: DERIVED or it is a defect*).
#:
#: Until this landing the command provisioned `{THIS_VERSION_ENCODING_ID}` —
#: **bundle version 1 alone** — while the kernel seals version 2. So the one
#: command this module exists to offer refused the only bundle the kernel can
#: emit, and the docstring above promised the opposite.
#:
#: > ***A COMMAND THAT REFUSES THE ONLY ARTEFACT ITS SYSTEM PRODUCES IS NOT A
#: > STRICT VERIFIER. IT IS ONE NOBODY CAN USE.***
#:
#: ⚠ **THIS IS A CALLER'S DECISION AND NOT A DEFAULT** (`BV-004`, untouched).
#: `parse` still has no default and still refuses to assume a profile; what
#: changed is that this caller — which recognises both, and
#: *"the old one is never dropped"* — now says so explicitly. `INTEROP/`'s
#: version-1 bundles stay verifiable forever, which is the point of the rule.
#:
#: ⚠ **DERIVED FROM THE TWO GOVERNED DECLARATIONS**, so a third version added to
#: `RECOGNISED_BUNDLE_VERSIONS` arrives here without anyone editing this file,
#: and a version REMOVED from it disappears here too. A second literal list
#: would be the forbidden drift.
PROVISIONED_ENCODING_IDS = frozenset(
    _bundle.ENCODING_ID_BY_BUNDLE_VERSION[version]
    for version in _bundle.RECOGNISED_BUNDLE_VERSIONS)

_PEM_KEYS = ("certificate_pem", "public_key_pem")
_PEM_FORMATS = {"certificate_pem": "x509-der", "public_key_pem": "spki-der"}


def _pem_body(text: str) -> bytes:
    lines = [ln.strip() for ln in text.strip().splitlines()]
    body = "".join(ln for ln in lines if ln and not ln.startswith("-----"))
    try:
        return base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SystemExit(f"refused: a PEM body did not decode: {exc}")


def build_trust_list(entries: dict) -> witness.WitnessTrustList:
    """A `WitnessTrustList` from the out-of-band JSON. **Refuses; never guesses.**

    An entry naming no key material at all is refused rather than skipped: a
    trust list silently one anchor short is a verifier that reports
    `witness-not-anchored` for a witness the operator believes they provisioned.
    """
    anchors = {}
    for ref, entry in entries.items():
        if not isinstance(entry, dict):
            raise SystemExit(f"refused: trust-list entry {ref!r} is not an object")
        chosen = [k for k in _PEM_KEYS if entry.get(k)]
        if entry.get("key_material_hex"):
            chosen.append("key_material_hex")
        if len(chosen) != 1:
            raise SystemExit(
                f"refused: trust-list entry {ref!r} names {len(chosen)} of "
                f"{sorted(_PEM_KEYS) + ['key_material_hex']}; exactly one is "
                "required, because a verifier that picks among two has chosen "
                "which representation to trust")
        key = chosen[0]
        if key == "key_material_hex":
            try:
                material = bytes.fromhex(entry[key])
            except ValueError as exc:
                raise SystemExit(f"refused: {ref!r} key_material_hex: {exc}")
            fmt = entry.get("format", "ed25519-raw")
        else:
            material = _pem_body(entry[key])
            fmt = entry.get("format", _PEM_FORMATS[key])
        anchors[ref] = witness.Anchor(witness_key_ref=ref, key_material=material,
                                      format=fmt)
    return witness.WitnessTrustList(anchors)


def _load_json(path: str, what: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
    except OSError as exc:
        raise SystemExit(f"refused: cannot read the {what}: {exc}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"refused: the {what} is not JSON: {exc}")
    if not isinstance(value, dict):
        raise SystemExit(f"refused: the {what} is not a JSON object")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m boundry_verify",
        description="Verify one Boundry verification bundle and print a verdict "
                    "per rung. Provisioned inputs have no defaults.",
        epilog="ATTESTED exits 0; UNATTESTED, REFUTED and ALTERED all exit 1 — "
               "read the OVERALL word, never the exit code.")
    parser.add_argument("bundle", help="path to the bundle (CBOR)")
    parser.add_argument("--key-directory", required=True, metavar="PATH",
                        help="out-of-band key directory JSON (REQUIRED; BV-012)")
    parser.add_argument("--witness-trust-list", metavar="PATH", default=None,
                        help="out-of-band witness trust list JSON. OMITTING it "
                             "means this verifier was never provisioned to "
                             "anchor a witness, which is a different fact from "
                             "an empty list")
    parser.add_argument("--json", action="store_true",
                        help="emit the report as JSON on stdout")
    parser.add_argument("--max-bundle-bytes", type=int, default=4 * 1024 * 1024,
                        metavar="N", help="BV-023 bound on the bundle")
    parser.add_argument("--der-max-bytes", type=int, default=4 * 1024 * 1024,
                        metavar="N", help="BV-023 bound on token/key DER")
    parser.add_argument("--der-max-depth", type=int, default=64, metavar="N")
    parser.add_argument("--der-max-elements", type=int, default=100_000,
                        metavar="N")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        data = open(args.bundle, "rb").read()
    except OSError as exc:
        raise SystemExit(f"refused: cannot read the bundle: {exc}")

    # ⚠ **A REFUSAL THE DIRECTORY RAISES IS STILL A REFUSAL.** Every
    # `KeyDirectoryError` — the shape checks, KD-011, KD-012, an unknown status,
    # a broken succession — used to travel straight out of `main` as an
    # uncaught exception, so the one command answered a malformed directory with
    # a traceback into this package's internals. `ERR-P4-002`: an implementation
    # that cannot answer SAYS SO, and a stranger is owed the same `refused:`
    # line here as everywhere else.
    try:
        directory = KeyDirectory(_load_json(args.key_directory, "key directory"))
    except KeyDirectoryError as exc:
        raise SystemExit(f"refused: the key directory is not usable: {exc}")
    trust_list = None
    if args.witness_trust_list is not None:
        trust_list = build_trust_list(
            _load_json(args.witness_trust_list, "witness trust list"))

    limits = der.Limits(max_bytes=args.der_max_bytes,
                        max_depth=args.der_max_depth,
                        max_elements=args.der_max_elements)

    try:
        parsed = _bundle.parse(
            data,
            recognised_encodings=PROVISIONED_ENCODING_IDS,
            max_bundle_bytes=args.max_bundle_bytes)
    except _bundle.BundleError as exc:
        # ⚠ A bundle that will not parse is REFUSED, and the refusal is NOT a
        # verdict about the record. It is reported as what it is and the process
        # exits 1 without printing an outcome word it has not earned.
        print(f"REFUSED AT PARSE: {exc}", file=sys.stderr)
        return 1

    report = verify_bundle(
        parsed, directory=directory, witness_trust_list=trust_list,
        token_verifiers={RFC3161_KIND: token_rfc3161.make_verifier(limits=limits)},
        recognised_form_tags=RECOGNISED_PAYLOAD_FORM_TAGS,
        recognised_signature_forms=frozenset({THIS_ERA_SIGNATURE_FORM}),
        key_reduction_limits=limits)

    provisioning = {
        # ⚠ **THE ECHO REPORTS WHAT WAS PROVISIONED, NOT ONE MEMBER OF IT.**
        # The values here are *"echoed on every run so a reader never has to
        # guess what a verdict was measured under"*, and a single id printed
        # while two were accepted would be exactly such a guess.
        "encoding_ids": sorted(PROVISIONED_ENCODING_IDS),
        "max_bundle_bytes": args.max_bundle_bytes,
        "der_limits": {"max_bytes": limits.max_bytes,
                       "max_depth": limits.max_depth,
                       "max_elements": limits.max_elements},
        "token_verifiers": [RFC3161_KIND],
        "anchor_formats": list(key_forms.REDUCIBLE_FORMATS),
        "witness_trust_list": ("NOT PROVISIONED" if trust_list is None
                               else f"{len(trust_list)} anchor(s)"),
        "recognised_form_tags": sorted(RECOGNISED_PAYLOAD_FORM_TAGS),
        "recognised_signature_forms": [THIS_ERA_SIGNATURE_FORM],
    }

    if args.json:
        print(json.dumps({"overall": report.overall,
                          "provisioning": provisioning,
                          "verdicts": [v.as_dict() for v in report.verdicts]},
                         indent=2, sort_keys=True))
    else:
        print(report.summary())
        # ⚠ ECHOED ON EVERY RUN. A verdict measured under bounds nobody recorded
        # is a verdict nobody can reproduce, and BV-023 makes the bounds the
        # operator's decision rather than this build's.
        print("\nPROVISIONED FOR THIS RUN (BV-004, BV-023 — no defaults in "
              "substance):")
        for key, value in provisioning.items():
            print(f"  {key}: {value}")

    return 0 if report.overall == ATTESTED else 1


if __name__ == "__main__":       # pragma: no cover
    sys.exit(main())
