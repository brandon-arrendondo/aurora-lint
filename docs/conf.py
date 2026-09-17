# Sphinx configuration for aurora-lint Developer Guide

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_project_facts  # noqa: E402

project = 'aurora-lint'
author = 'BISSELL Homecare, Inc.'
copyright = '2025-2026, BISSELL Homecare, Inc. Licensed under CC BY 4.0'

extensions = []

templates_path = []
exclude_patterns = ['screenshots/README.md']

# -- Self-description substitutions, computed fresh on every build --
#
# These exist so a number derived from this checkout (rule counts, which
# rules use the macro-expansion engine) is never hand-typed into a .rst
# file, where it can only go stale the way check_project_facts.py's own
# module docstring documents happening repeatedly. Anything MEASURED
# (precision, recall, throughput) does NOT belong here -- see that
# script's docstring on why, and use `bench render-docs` / benchmarking_db
# instead.
_facts = check_project_facts.export_facts()


def _oxford_list(items: list[str]) -> str:
    if not items:
        return "no rules"
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + f", and {items[-1]}"


rst_epilog = f"""
.. |rules_total| replace:: {_facts['rules_total']}
.. |rules_enabled| replace:: {_facts['rules_enabled']}
.. |rules_disabled| replace:: {_facts['rules_disabled']}
.. |macro_expand_rule_count| replace:: {_facts['macro_expand_rule_count']}
.. |macro_expand_rule_list| replace:: {_oxford_list(_facts['macro_expand_rules'])}
"""

# -- HTML output (sphinx-rtd-theme) --
html_theme = 'sphinx_rtd_theme'
html_static_path = []

# -- LaTeX / PDF output --
latex_elements = {
    'papersize': 'letterpaper',
    'pointsize': '10pt',
    'preamble': r'''
\usepackage{enumitem}
\setlistdepth{9}
''',
}

latex_documents = [
    ('index', 'aurora-lint-developer-guide.tex', 'aurora-lint Developer Guide',
     'BISSELL Homecare, Inc.', 'manual'),  # CC BY 4.0
]
