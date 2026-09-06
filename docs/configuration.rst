Configuration
=============

Manifest File
-------------

The rules manifest TOML file controls which rules are active and their severity.
The default manifest (``rules_templates/rules-all.toml``) enables 307 of the 311 tracked rules.
The other 4 are tracked but not implemented — see `Tracked but not implemented`_ below.

::

    # Use default (all rules enabled)
    aurora-lint /path/to/code

    # Use a custom manifest
    aurora-lint --manifest my-rules.toml /path/to/code

Custom Manifest Format
----------------------

.. code-block:: toml

    [metadata]
    name = "My Project Rules"
    version = "1.0.0"
    description = "Custom CERT C rules for my project"
    cert_version = "2016"

    [rules.ARR30-C]
    enabled = true
    severity = "High"
    description = "Do not form or use out-of-bounds pointers or array subscripts"
    category = "Rule"
    cert_id = "ARR30-C"

    [rules.STR31-C]
    enabled = false  # Disable this rule
    severity = "Medium"
    description = "Guarantee that storage for strings has sufficient space"
    category = "Rule"
    cert_id = "STR31-C"

Supported CERT C Rules
----------------------

311 rules are tracked across 17 categories; 307 are implemented and enabled by
default (the remaining 4 are tracked but not implemented — see
`Tracked but not implemented`_ below):

==========  ======  ===========================================================
Category    Count   Rules
==========  ======  ===========================================================
**API**     9       API00-C through API10-C (selected)
**ARR**     9       ARR00-C through ARR39-C (selected)
**CON**     23      CON01-C through CON50-C (selected)
**DCL**     31      DCL00-C through DCL41-C (selected)
**ENV**     8       ENV01-C through ENV34-C (selected)
**ERR**     11      ERR00-C through ERR34-C (selected)
**EXP**     31      EXP00-C through EXP47-C (selected)
**FIO**     35      FIO01-C through FIO51-C (selected)
**FLP**     13      FLP00-C through FLP37-C (selected)
**INT**     23      INT00-C through INT36-C (selected)
**MEM**     17      MEM00-C through MEM36-C (selected)
**MSC**     10      MSC04-C through MSC41-C (selected)
**POS**     20      POS01-C through POS54-C (selected)
**PRE**     16      PRE00-C through PRE32-C (selected)
**SIG**     7       SIG00-C through SIG35-C (selected)
**STR**     16      STR00-C through STR38-C (selected)
**WIN**     6       WIN00-C through WIN30-C (selected)
==========  ======  ===========================================================

For the full list, see ``rules_templates/rules-all.toml`` or the rule source files
in ``src/rules/cert_c/``.

Tracked but not implemented
----------------------------

4 of the 311 tracked rules have a rule directory and a manifest entry but no
detection logic (no ``.rs`` file). This is a deliberate policy, not a gap:
aurora-lint does not implement against incomplete CERT-C rule content, since there is
ample well-established work to do and a stub implementation would mean
inventing a rule CERT itself has not written.

Two are parked on upstream CERT publishing real content for the rule:

- **ENV04-C** — *Protect programs whose behavior can be controlled by
  environment variables*. CERT's page carries only OpenMP environment-variable
  framing; severity, likelihood, priority and level are all unscored, and
  there is no formal description, no compliant/noncompliant examples, and no
  CWE mapping. `CERT wiki page
  <https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/recommendations/environment-env/env04-c>`_.
  Will be implemented once CERT ships real content; tracked as a gate task
  until then.
- **MSC25-C** — *Do not use insecure or weak cryptographic algorithms*.
  CERT's scraped description is the single sentence "This rule is a stub,"
  with zero CWE references. `CERT wiki page
  <https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard/recommendations/miscellaneous-msc/msc25-c>`_.
  Will be implemented once CERT ships real content; tracked as a gate task
  until then.

The other two are ordinary backlog — CERT's content for them is complete, they
are simply not yet written:

- **MSC18-C** — CERT's description and risk assessment are complete (severity
  Medium, 7 CWE references), and one ``pass`` fixture is already staged.
- **MSC19-C** — CERT's description and risk assessment are complete
  (severity Low), and 2 ``fail`` + 2 ``pass`` fixtures are already staged —
  the closest of the 4 to being implementable.
