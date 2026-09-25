# Boundry Verify — contact

Every value below is read from `manifest.json`, which ships beside this file. They are written
there from one declaration, so this page and the manifest cannot disagree.

| field | where it is | what it is |
|---|---|---|
| maintainer | `manifest.json` `author.name` | who publishes this package |
| contact address | `manifest.json` `author.email` | questions and problems |
| security contact | `manifest.json` `author.email` | the same address. There is no separate one, and a report is welcome at it |
| documentation | `manifest.json` `documentation` (and `homepage`, `support`) | the page this package is described on |
| privacy policy | `manifest.json` `privacy_policies[0]` | what leaves your machine, hosted |
| licence | `LICENSE.txt`, beside this file; `manifest.json` `license` | free to use; not open source. You may install and use it unmodified; you may not modify, distribute or publish it |
| source | not published | the package ships as built. What it does is checkable from what is in it: read the code beside this file, and run the checks |

If a measurement of yours disagrees with anything these documents say, the measurement wins, and
the contact address is the place to say so.

*Held by:* `the_manifests_contact_fields_are_real_and_agree_with_the_documents`, which reads each
of those manifest fields and requires a real address rather than a placeholder; and
`each_held_by_name_in_the_documents_RESOLVES`, which resolves every name on a *Held by* line in
these three documents. Run them yourself:
`python3 -I -B -m unittest discover -s server/boundry_connector -t server`.
