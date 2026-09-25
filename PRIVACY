# Boundry Verify — what leaves the machine

This is the same policy as the hosted one, which `manifest.json` names in `privacy_policies`. If
the two ever differ, the hosted page is the published one and this file is the one that shipped
with your copy; neither claims more than the other.

## 1 · The connector sends nothing anywhere

It has no telemetry, no analytics, no accounts and no crash reporting. It opens no network
connection and contacts no server — ours or anyone else's. Nothing about you, your machine or your
use of it reaches the maintainer, because there is no path by which it could.

*Held by:* the checks `it_opens_no_socket_and_contacts_no_endpoint`,
`it_neither_writes_nor_subscribes` and `it_imports_no_emitter_and_no_mcp_package`, which walk every
module in this package by AST against a declared set. Run them yourself:
`python3 -I -B -m unittest discover -s server/boundry_connector -t server`.

⚠ The one write the server performs is to standard output — that IS the local transport, and it is
a named exemption in those checks rather than a silent skip. Putting a reply on the pipe is the
whole job.

## 2 · ⚠ BUT YOUR CONVERSATION IS NOT PRIVATE, AND THAT IS THE POINT OF IT

The connector exists to show records to an AI assistant. Everything a tool returns becomes part of
your conversation, exactly as if you had pasted it into the chat. It is sent to your assistant's
provider — for Claude, Anthropic — and handled under that provider's terms and privacy policy, not
this one.

**Your conversation is not private to your computer.** The connector is private in the sense
that it sends nothing itself, and not in the sense that what you read with it
stays on your machine. This is stated plainly, rather than in a footnote, because it is the
single thing a reader is most likely to get backwards. The two sections around it are not in
tension: the first is about the server, this one is about the conversation the server feeds.

## 3 · So: do not point it at client data

Do not point it at confidential, personal or client data that you would not paste into a chat.

Left unset, it reads the two packaged folders of synthetic records and nothing else — the
demonstration corpus and the evaluation kit's evidence. It does not write, change or delete files,
and it creates no files of its own.

*Held by:* `corpus.allowed_roots` in this package — its default is those two packaged synthetic
roots, not everything — and the check
`UNSET_roots_mean_the_two_packaged_roots_and_nothing_else`.

## 4 · Sharing, keeping, removing

Nothing is collected, so nothing is shared, sold or kept. To remove the connector, uninstall it in
Claude Desktop; it leaves behind no data of its own. How long your conversations are kept is
governed by your assistant provider's settings, not by this package.

It is a developer and evaluation tool, and is not directed at children.

## 5 · The model step in the workload, if it is ever live

This package reads records; it does not run work. If the work that PRODUCED those records is ever
run against a live model provider rather than a stub, that is a second path off a machine, distinct from your
conversation, and it is not this connector's path. It is named here before it exists rather than
after.

*Held by:* `E5_the_conduct_line_result_ships_with_its_instruments_digests`, which reads the kit's
shipped result: no model was loaded or called in governed operation, with the digest of the
instrument that measured it.

## 6 · Changes, and what is not claimed

If this policy changes, the hosted page is updated and its date with it. A change to what leaves
your machine is stated at the top of that page.

<!-- WORDS-NOT-USED:START -->
No claim is made that anyone cannot read your data, that records are
tamper-proof, immutable, or guaranteed.
<!-- WORDS-NOT-USED:END -->

What IS claimed is what `README.md` says, and every claim there names the check that holds it.
