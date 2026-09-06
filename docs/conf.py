# Sphinx configuration for aurora-lint Developer Guide

project = 'aurora-lint'
author = 'BISSELL Homecare, Inc.'
copyright = '2025-2026, BISSELL Homecare, Inc. Licensed under CC BY 4.0'

extensions = []

templates_path = []
exclude_patterns = ['screenshots/README.md']

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
