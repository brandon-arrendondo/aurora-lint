Configuration
=============

Manifest File
-------------

The rules manifest TOML file controls which rules are active and their severity.
The default manifest (``rules_templates/rules-all.toml``) enables 305 of the 311 implemented rules.

::

    # Use default (all rules enabled)
    sqc /path/to/code

    # Use a custom manifest
    sqc --manifest my-rules.toml /path/to/code

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

311 rules are implemented across 17 categories (305 enabled by default):

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
