#!/usr/bin/env python3
"""
Scrape the SEI CERT C Coding Standard from cmu-sei.github.io/secure-coding-standards.

The standard used to live on a Confluence wiki (wiki.sei.cmu.edu); that host
now 301-redirects to a statically-generated Nuxt/Nuxt Content site. The site
is a fully client-rendered SPA -- the server-rendered HTML shell has no rule
content in it at all -- but each page also serves a `_payload.json` next to
it containing the page's Nuxt Content AST (used to hydrate the Vue app) plus
the full site navigation tree. This script talks to that JSON API directly
rather than scraping rendered HTML.

This script:
1. Fetches the site's navigation tree (one request) to enumerate every rule
   and recommendation ID, title, and path.
2. Fetches each item's `_payload.json` and walks its content AST for
   metadata (risk assessment table, CWE refs) and code examples.
3. Generates TOML metadata files (preserving existing files -- see
   generate_toml_metadata).
4. Implements rate limiting to be respectful of the site.

Usage:
    python3 scripts/scrape_cert_wiki.py [--delay SECONDS] [--output DIR] [--type rule|rec|all] [--force]
"""

import re
import sys
import time
import json
import argparse
import requests
import textwrap
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass

# Configuration
BASE_URL = "https://cmu-sei.github.io/secure-coding-standards"
STANDARD_PATH = "/sei-cert-c-coding-standard"
DEFAULT_DELAY = 3.0  # Seconds between requests (conservative - no robots.txt found)
USER_AGENT = "CERT-C-Scraper/2.0 (Educational Purpose)"

# Output configuration - directly to src/rules/cert_c/
BASE_OUTPUT_DIR = "src/rules/cert_c"


@dataclass
class ItemMetadata:
    """Structured metadata for a rule or recommendation from the site"""
    id: str
    item_type: str  # "rule" or "recommendation"
    category: str
    number: int
    title: str

    # Risk assessment
    severity: Optional[str] = None
    likelihood: Optional[str] = None
    priority: Optional[str] = None
    level: Optional[str] = None

    # References
    wiki_url: str = ""
    cert_version: Optional[str] = None  # CERT C standard version
    last_modified: Optional[str] = None  # Not exposed by the new site (see NOTE in parse_item_page)
    cwe: List[str] = None
    related_rules: List[str] = None
    related_recommendations: List[str] = None

    # Content
    description: str = ""

    def __post_init__(self):
        if self.cwe is None:
            self.cwe = []
        if self.related_rules is None:
            self.related_rules = []
        if self.related_recommendations is None:
            self.related_recommendations = []


# ---------------------------------------------------------------------------
# Nuxt payload plumbing
# ---------------------------------------------------------------------------
#
# Nuxt's payload format ("devalue") is a flattened array: `data[0]` is the
# root, and any int found where a value is expected is an index into `data`
# to dereference (this is how it represents shared/circular references
# compactly). `["ShallowReactive", i]` is Nuxt's Vue-reactivity wrapper and
# just means "dereference i". `deref_payload` below resolves this back into
# plain nested dicts/lists/strings, memoized so shared references and any
# cycles are only visited once.


def deref_payload(data: List[Any], index: int, memo: Dict[int, Any]) -> Any:
    if index in memo:
        return memo[index]
    value = data[index]
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        memo[index] = out
        for key, v in value.items():
            out[key] = deref_payload(data, v, memo) if isinstance(v, int) else v
        return out
    if isinstance(value, list):
        if value and value[0] == "ShallowReactive":
            resolved = deref_payload(data, value[1], memo)
            memo[index] = resolved
            return resolved
        out_list: List[Any] = []
        memo[index] = out_list
        for v in value:
            out_list.append(deref_payload(data, v, memo) if isinstance(v, int) else v)
        return out_list
    return value


def node_text(node: Any) -> str:
    """Flatten a Nuxt Content AST node (or plain string) to its text content.

    A node is `[tag, props, *children]`; children may themselves be nodes or
    bare strings. Used for heading/table-cell/paragraph text where we don't
    care about inline formatting (bold, links, etc.), only the text.
    """
    if isinstance(node, str):
        return node
    if isinstance(node, list) and len(node) >= 1 and isinstance(node[0], str):
        return "".join(node_text(c) for c in node[2:])
    return ""


class WikiScraper:
    """Client for the CERT C secure-coding-standards site's Nuxt payload API"""

    def __init__(self, delay: float = DEFAULT_DELAY):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.delay = delay
        self.last_request_time = 0.0

    def _rate_limit(self):
        """Implement rate limiting between requests"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_request_time = time.time()

    def fetch_payload_root(self, path: str) -> Optional[Dict[str, Any]]:
        """Fetch and deref `{path}/_payload.json`'s root state object (the
        dict at `data[2]` in every Nuxt payload we've seen from this site --
        it holds keys like `page-{path}`, `sidebar-...`, `global-navigation`).
        """
        self._rate_limit()
        url = f"{BASE_URL}{path}/_payload.json"
        try:
            print(f"  Fetching: {url}")
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            memo: Dict[int, Any] = {}
            return deref_payload(data, 2, memo)
        except (requests.RequestException, json.JSONDecodeError, IndexError, KeyError) as e:
            print(f"  ✗ Error fetching {url}: {e}")
            return None

    def discover_items(self) -> List[Tuple[str, str, str, str, str]]:
        """
        Enumerate every rule/recommendation from the standard's sidebar nav
        tree (one HTTP request covers the whole site -- the old Confluence
        scraper needed a request per category page just to list items).

        Returns: list of (item_id, title, item_type, category, path) tuples.
        """
        print("Discovering items from site navigation tree...")
        root = self.fetch_payload_root(STANDARD_PATH)
        if not root:
            print("  ✗ Failed to fetch navigation tree")
            return []

        sidebar_key = f"sidebar-{STANDARD_PATH.strip('/').replace('/', '-')}"
        sidebar = root.get(sidebar_key)
        if not sidebar:
            print(f"  ✗ No '{sidebar_key}' key in payload root (keys: {list(root.keys())})")
            return []

        item_pattern = re.compile(r"^([A-Z]{3})(\d{2})-C\.?\s*(.*)$")
        items: List[Tuple[str, str, str, str, str]] = []
        seen_ids = set()

        def walk(node: Dict[str, Any]):
            title = node.get("title", "")
            path = node.get("path", "")
            match = item_pattern.match(title)
            if match and path:
                category, number, rest = match.groups()
                item_id = f"{category}{number}-C"
                if item_id not in seen_ids:
                    seen_ids.add(item_id)
                    item_type = "rule" if "/rules/" in path else "recommendation"
                    items.append((item_id, rest.strip(), item_type, category, path))
            for child in node.get("children") or []:
                walk(child)

        for top in sidebar:
            walk(top)

        print(f"✓ Discovered {len(items)} items")
        return items

    def parse_item_page(
        self, item_id: str, path: str, item_type: str
    ) -> Optional[Tuple[ItemMetadata, List[Tuple[str, str]], List[Tuple[str, str]]]]:
        """
        Parse an individual rule or recommendation page for all content.

        Returns: (ItemMetadata, non_compliant_examples, compliant_examples) or None on error
        """
        root = self.fetch_payload_root(path)
        if not root:
            return None

        page_key = f"page-{path}"
        page = root.get(page_key)
        if not page:
            print(f"  ✗ No '{page_key}' key in payload root")
            return None

        match = re.match(r"^([A-Z]{3})(\d{2})-C$", item_id)
        if not match:
            return None
        category, number = match.groups()

        item = ItemMetadata(
            id=item_id,
            item_type=item_type,
            category=category,
            number=int(number),
            title="",
            wiki_url=f"{BASE_URL}{path}",
        )

        title = page.get("title", "")
        item.title = re.sub(rf"^{re.escape(item_id)}\.?\s*", "", title)

        # cert_version will be added in the future once source is identified
        item.cert_version = "2016 Edition (Wiki)"
        # NOTE: the new site's payload doesn't expose a per-page last-modified
        # date anywhere we've found (unlike the old Confluence footer). Left
        # as None; generate_toml_metadata() treats a missing wiki-side date
        # as "can't compare, skip" for existing TOML files, so this doesn't
        # cause spurious overwrites -- it only means newly-created TOMLs get
        # last_modified = "Unknown" until a real source is identified. See
        # task 325.
        item.last_modified = None

        body = page.get("body") or {}
        body_value = body.get("value") or []

        item.description = _extract_description(body_value)
        _extract_risk_assessment(body_value, item)
        _extract_cwe_refs(body_value, page, item)
        _extract_related_items(body_value, item_id, item)

        non_compliant, compliant = extract_code_examples(body_value)

        return (item, non_compliant, compliant)


# ---------------------------------------------------------------------------
# Content-AST extraction (metadata)
# ---------------------------------------------------------------------------

HEADING_TAGS = ("h1", "h2", "h3", "h4", "h5")


def _is_element(node: Any) -> bool:
    return isinstance(node, list) and len(node) >= 2 and isinstance(node[0], str)


def _extract_description(body_value: List[Any]) -> str:
    """Extract the description from the top-level paragraphs before the
    first heading after the title (mirrors the old scraper's "first few
    paragraphs" heuristic)."""
    desc_parts = []
    for node in body_value:
        if not _is_element(node):
            continue
        if node[0] in HEADING_TAGS:
            if desc_parts:
                break
            continue
        if node[0] == "p":
            text = node_text(node).strip()
            if text:
                desc_parts.append(text)
                if len(desc_parts) >= 3:
                    break
    return "\n\n".join(desc_parts)


def _extract_risk_assessment(body_value: List[Any], item: ItemMetadata) -> None:
    """Extract severity/likelihood/priority/level from the risk assessment table.

    Table AST shape: ["table", {}, ["thead", {}, ["tr", {}, ["th", {}, text], ...]],
    ["tbody", {}, ["tr", {}, ["td", {}, text-or-nested], ...]]].
    """
    for node in body_value:
        if not _is_element(node) or node[0] != "table":
            continue
        thead = next((c for c in node[2:] if _is_element(c) and c[0] == "thead"), None)
        tbody = next((c for c in node[2:] if _is_element(c) and c[0] == "tbody"), None)
        if not thead or not tbody:
            continue
        header_row = next((c for c in thead[2:] if _is_element(c) and c[0] == "tr"), None)
        if not header_row:
            continue
        headers = [node_text(c).strip().lower() for c in header_row[2:] if _is_element(c)]
        if "severity" not in headers and "likelihood" not in headers:
            continue
        data_row = next((c for c in tbody[2:] if _is_element(c) and c[0] == "tr"), None)
        if not data_row:
            continue
        cells = [c for c in data_row[2:] if _is_element(c)]
        for i, header in enumerate(headers):
            if i >= len(cells):
                continue
            value = node_text(cells[i]).strip()
            if header == "severity":
                item.severity = value
            elif header == "likelihood":
                item.likelihood = value
            elif header == "priority":
                item.priority = value
            elif header == "level":
                item.level = value
        return  # only the first matching table (Risk Assessment section)


def _extract_cwe_refs(body_value: List[Any], page: Dict[str, Any], item: ItemMetadata) -> None:
    """Extract referenced CWE IDs from the page body text and frontmatter tags."""
    cwe_pattern = re.compile(r"CWE-(\d+)")
    for match in cwe_pattern.finditer(json.dumps(body_value)):
        cwe_id = f"CWE-{match.group(1)}"
        if cwe_id not in item.cwe:
            item.cwe.append(cwe_id)
    for tag in (page.get("meta") or {}).get("tags") or []:
        tag_match = re.match(r"cwe-(\d+)$", tag, re.IGNORECASE)
        if tag_match:
            cwe_id = f"CWE-{tag_match.group(1)}"
            if cwe_id not in item.cwe:
                item.cwe.append(cwe_id)


def _extract_related_items(body_value: List[Any], item_id: str, item: ItemMetadata) -> None:
    """Extract related rule/recommendation IDs from the first 'Related' section.

    NOTE: `item.related_rules`/`related_recommendations` aren't currently
    written to the generated TOML (generate_toml_metadata never emits them),
    so this is best-effort and not load-bearing -- kept for parity/future use.
    """
    rule_pattern = re.compile(r"\b([A-Z]{3}\d{2}-C)\b")

    heading_idx = None
    for i, node in enumerate(body_value):
        if _is_element(node) and node[0] in ("h2", "h3", "h4") and "related" in node_text(node).lower():
            heading_idx = i
            break
    if heading_idx is None or heading_idx + 1 >= len(body_value):
        return

    section_text = node_text(body_value[heading_idx + 1])
    for match in rule_pattern.finditer(section_text):
        related_id = match.group(1)
        if related_id == item_id:
            continue
        related_num = int(related_id[3:5])
        start = max(0, match.start() - 50)
        end = min(len(section_text), match.end() + 50)
        context = section_text[start:end].lower()
        if "recommendation" in context or related_num < 30:
            if related_id not in item.related_recommendations:
                item.related_recommendations.append(related_id)
        else:
            if related_id not in item.related_rules:
                item.related_rules.append(related_id)


# ---------------------------------------------------------------------------
# Content-AST extraction (code examples)
# ---------------------------------------------------------------------------


def sanitize_code(code: str) -> str:
    """
    Clean invisible/non-printable characters from code.
    Removes non-breaking spaces, zero-width spaces, etc.
    """
    code = code.replace(" ", " ")
    code = code.replace("​", "")
    code = code.replace("‌", "")
    code = code.replace("‍", "")
    code = code.replace("﻿", "")  # Zero-width no-break space (BOM)
    return code


def _find_pre_child(code_block_node: List[Any]) -> Optional[List[Any]]:
    for child in code_block_node[2:]:
        if _is_element(child) and child[0] == "pre":
            return child
    return None


def extract_code_examples(
    body_value: List[Any],
) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """
    Extract compliant and non-compliant code examples from a page's content AST.

    Real code examples are wrapped by the site's Markdown pipeline in a
    `["code-block", {"quality": "good"|"bad"}, ["pre", {"code": ...}, ...]]`
    node. Sample/console output shown alongside an example (e.g. "The output
    is as follows:" followed by a block of PRNG numbers) is emitted as a bare
    sibling `["pre", {...}]` node, NOT wrapped in `code-block` -- so it's
    structurally excluded here without needing content heuristics (contrast
    with the old Confluence-HTML scraper, which had no such signal and had
    to guess via prose cues / "does this look like C" heuristics; see task
    137). The `quality` flag is also more reliable than the old heading-text
    matching for classifying which section a code block belongs to.

    Returns: (non_compliant_examples, compliant_examples)
    Each tuple is (example_name, code)
    """
    non_compliant: List[Tuple[str, str]] = []
    compliant: List[Tuple[str, str]] = []

    current_bucket: Optional[str] = None
    current_name: Optional[str] = None
    nc_count = 0
    c_count = 0

    for node in body_value:
        if not _is_element(node):
            continue
        tag = node[0]

        if tag in ("h2", "h3", "h4", "h5"):
            heading_text = node_text(node)
            heading_lower = heading_text.lower()
            clean_name = heading_text
            for remove_phrase in [
                "Noncompliant Code Example",
                "Compliant Solution",
                "Non-Compliant Code Example",
            ]:
                clean_name = re.sub(re.escape(remove_phrase), "", clean_name, flags=re.IGNORECASE)
            clean_name = clean_name.strip(" :-")
            current_name = clean_name if len(clean_name) >= 3 else None

            if "noncompliant" in heading_lower or "non-compliant" in heading_lower:
                current_bucket = "noncompliant"
                nc_count = 0
            elif "compliant" in heading_lower and "non" not in heading_lower:
                current_bucket = "compliant"
                c_count = 0
            else:
                current_bucket = None
            continue

        if tag != "code-block":
            continue

        props = node[1] if isinstance(node[1], dict) else {}
        pre_node = _find_pre_child(node)
        if pre_node is None:
            continue
        pre_props = pre_node[1] if isinstance(pre_node[1], dict) else {}
        code = sanitize_code(pre_props.get("code", ""))
        if not code.strip():
            continue

        quality = props.get("quality")
        if quality == "bad":
            bucket = "noncompliant"
        elif quality == "good":
            bucket = "compliant"
        elif current_bucket is not None:
            bucket = current_bucket  # fall back to heading context if quality is absent
        else:
            continue

        if bucket == "noncompliant":
            nc_count += 1
            example_name = (
                sanitize_filename(current_name) if current_name else f"noncompliant_{len(non_compliant) + 1}"
            )
            if nc_count > 1:
                example_name = f"{example_name}_{nc_count}"
            non_compliant.append((example_name, code.strip()))
        else:
            c_count += 1
            example_name = sanitize_filename(current_name) if current_name else f"compliant_{len(compliant) + 1}"
            if c_count > 1:
                example_name = f"{example_name}_{c_count}"
            compliant.append((example_name, code.strip()))

    return non_compliant, compliant


def sanitize_filename(name: str) -> str:
    """Convert heading text to valid filename"""
    name = re.sub(r"[^\w\s-]", "", name)
    name = re.sub(r"[-\s]+", "_", name)
    name = name.strip("_")
    name = name.lower()
    if len(name) > 60:
        name = name[:60]
    return name


def save_code_examples(
    item_id: str,
    category: str,
    non_compliant: List[Tuple[str, str]],
    compliant: List[Tuple[str, str]],
    output_dir: str,
):
    """Save code examples as test files with proper header comments"""
    if not non_compliant and not compliant:
        return

    # Create nested test directories: ARR/ARR30-C/tests/fail and ARR/ARR30-C/tests/pass
    tests_dir = Path(output_dir) / category / item_id / "tests"
    fail_dir = tests_dir / "fail"
    pass_dir = tests_dir / "pass"

    fail_dir.mkdir(parents=True, exist_ok=True)
    pass_dir.mkdir(parents=True, exist_ok=True)

    # Save non-compliant examples
    for example_name, code in non_compliant:
        filename = f"wiki_{example_name}.c"
        filepath = fail_dir / filename

        header = f"""/*
 * Rule: {item_id}
 * Source: wiki
 * Status: FAIL - Should trigger {item_id} violation
 */

"""
        full_content = header + code
        filepath.write_text(full_content)
        print(f"    ✓ Saved non-compliant example: {filepath}")

    # Save compliant examples
    for example_name, code in compliant:
        filename = f"wiki_{example_name}.c"
        filepath = pass_dir / filename

        header = f"""/*
 * Rule: {item_id}
 * Source: wiki
 * Status: PASS - Compliant solution
 */

"""
        full_content = header + code
        filepath.write_text(full_content)
        print(f"    ✓ Saved compliant example: {filepath}")


def wrap_description(text: str, width: int = 80) -> str:
    """Wrap text to specified width while preserving paragraph breaks"""
    if not text:
        return ""

    # Clean unicode artifacts
    text = text.replace("\xa0", " ")

    paragraphs = text.split("\n\n")
    wrapped_paragraphs = []

    for para in paragraphs:
        # Remove existing line breaks within paragraph
        para = " ".join(para.split())
        # Wrap to width
        wrapped = textwrap.fill(para, width=width)
        wrapped_paragraphs.append(wrapped)

    return "\n".join(wrapped_paragraphs)


def parse_existing_toml_date(toml_path: Path) -> Optional[str]:
    """Extract last_modified date from existing TOML file"""
    try:
        with open(toml_path, "r") as f:
            content = f.read()
            match = re.search(r'last_modified\s*=\s*"([^"]+)"', content)
            if match:
                return match.group(1)
    except Exception as e:
        print(f"    ⚠ Could not read existing TOML: {e}")
    return None


def compare_dates(date1: Optional[str], date2: Optional[str]) -> int:
    """
    Compare two date strings in format "Month DD, YYYY"
    Returns: -1 if date1 < date2, 0 if equal, 1 if date1 > date2, 0 if can't compare
    """
    if not date1 or not date2:
        return 0

    try:
        from datetime import datetime

        d1 = datetime.strptime(date1, "%b %d, %Y")
        d2 = datetime.strptime(date2, "%b %d, %Y")
        if d1 < d2:
            return -1
        elif d1 > d2:
            return 1
        else:
            return 0
    except Exception:
        # If we can't parse, assume they're different to be safe
        return 0 if date1 == date2 else 1


def toml_inline_string(value: str) -> str:
    """TOML-encode a single-line string value.

    Prefer a literal string (single quotes, no escape processing) when the text
    has no single quote or control char; otherwise fall back to a properly
    escaped basic string. This prevents scraped titles that contain embedded
    double quotes (e.g. DCL16-C: 'Use "L," not "l,"...') from emitting invalid
    TOML. See task 200 / task 130 (build-time manifest validation).
    """
    if "'" not in value and "\n" not in value and "\r" not in value:
        return f"'{value}'"
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def toml_multiline_string(value: str) -> str:
    """TOML-encode multi-line text (e.g. a scraped description).

    Prefer a multi-line literal string (''' ... ''') so prose containing
    backslashes (\\x10, \\U, \\u, \\0, Windows paths like \\\\.\\) is taken
    verbatim — these are the exact sequences that broke 8 rule TOMLs before
    task 130 added validation. Fall back to an escaped multi-line basic string
    only if the text contains a triple single-quote, which a literal string
    cannot represent.
    """
    if "'''" not in value:
        return "'''\n" + value + "\n'''"
    escaped = value.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
    return '"""\n' + escaped + '\n"""'


def generate_toml_metadata(item: ItemMetadata, output_path: Path, force: bool = False):
    """
    Generate TOML metadata file for a rule or recommendation.

    If the file exists and force=False, only update if wiki content is newer.
    """

    # Check if file already exists
    if output_path.exists() and not force:
        # Check if wiki content is newer
        existing_date = parse_existing_toml_date(output_path)
        wiki_date = item.last_modified

        if existing_date and wiki_date:
            comparison = compare_dates(wiki_date, existing_date)
            if comparison <= 0:
                # Wiki content is same or older than existing TOML
                print(f"    ⊙ TOML up-to-date: {output_path} (wiki: {wiki_date}, local: {existing_date})")
                return
            else:
                # Wiki content is newer
                print(f"    ↻ Wiki updated: {wiki_date} > {existing_date}, regenerating...")
        else:
            # Can't compare dates, skip to be safe
            print(f"    ⊙ TOML exists: {output_path} (use --force to overwrite)")
            return

    # Wrap description for readability
    wrapped_desc = wrap_description(item.description, width=80)

    # Build TOML content manually for better control
    toml_lines = []

    # Metadata section
    toml_lines.append("[metadata]")
    toml_lines.append(f'id = "{item.id}"')
    toml_lines.append(f'type = "{item.item_type}"')
    toml_lines.append(f'category = "{item.category}"')
    toml_lines.append(f"number = {item.number}")
    toml_lines.append(f"title = {toml_inline_string(item.title)}")

    # Description with multi-line string (literal-string-encoded so scraped
    # backslashes/quotes can't produce invalid TOML — see task 200).
    if wrapped_desc:
        toml_lines.append("description = " + toml_multiline_string(wrapped_desc))
    else:
        toml_lines.append('description = ""')

    toml_lines.append(f'severity = "{item.severity or "Unknown"}"')
    toml_lines.append(f'likelihood = "{item.likelihood or "Unknown"}"')
    toml_lines.append(f'priority = "{item.priority or "Unknown"}"')
    toml_lines.append(f'level = "{item.level or "Unknown"}"')
    toml_lines.append(f'cert_version = "{item.cert_version or "Unknown"}"')
    toml_lines.append(f'last_modified = "{item.last_modified or "Unknown"}"')
    toml_lines.append("")

    # Rules section (enabled = false by default for new rules)
    toml_lines.append(f"[rules.cert_c.{item.id}]")
    toml_lines.append("enabled = false")
    toml_lines.append("")

    # References section
    toml_lines.append("[references]")
    toml_lines.append(f'wiki = "{item.wiki_url}"')

    if item.cwe:
        cwe_list = ", ".join([f'"{cwe}"' for cwe in item.cwe])
        toml_lines.append(f"cwe = [{cwe_list}]")
    else:
        toml_lines.append("cwe = []")

    toml_lines.append("")

    # Write to file
    with open(output_path, "w") as f:
        f.write("\n".join(toml_lines))


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description="Scrape CERT C secure-coding-standards site and generate TOML metadata")
    parser.add_argument(
        "--delay", type=float, default=DEFAULT_DELAY, help=f"Delay between requests in seconds (default: {DEFAULT_DELAY})"
    )
    parser.add_argument("--output", type=str, default=BASE_OUTPUT_DIR, help=f"Output base directory (default: {BASE_OUTPUT_DIR})")
    parser.add_argument("--categories", type=str, nargs="+", help="Specific categories to scrape (e.g., ARR MEM), default: all")
    parser.add_argument("--type", choices=["rule", "rec", "all"], default="all", help="Scrape rules, recommendations, or both (default: all)")
    parser.add_argument("--force", action="store_true", help="Force overwrite existing TOML files")
    args = parser.parse_args()

    print("=" * 60)
    print("CERT C Standard Scraper - TOML Generation")
    print("=" * 60)
    print(f"Rate limit: {args.delay}s between requests")
    print("  (Note: No robots.txt found - using conservative default)")
    print(f"Output directory: {args.output}")
    print(f"Scraping: {args.type}")
    print(f"Force overwrite: {args.force}")
    print()

    # Create scraper
    scraper = WikiScraper(delay=args.delay)

    # Discover every rule/recommendation from the site's nav tree in one shot
    all_discovered = scraper.discover_items()
    print()

    if not all_discovered:
        print("✗ No items discovered from site. Exiting.")
        return 1

    type_filter = {"rule": {"rule"}, "rec": {"recommendation"}, "all": {"rule", "recommendation"}}[args.type]
    category_filter = set(args.categories) if args.categories else None

    all_items = [
        (item_type, category, item_id, title, path)
        for item_id, title, item_type, category, path in all_discovered
        if item_type in type_filter and (category_filter is None or category in category_filter)
    ]

    print(f"✓ Total items to scrape: {len(all_items)} (of {len(all_discovered)} discovered)")
    print()

    # Parse each item
    print("=" * 60)
    print("Parsing individual pages and generating TOML...")
    print("=" * 60)
    parsed_items = []
    skipped_items = []
    new_items = []
    updated_items = []

    for i, (item_type, category, item_id, title, path) in enumerate(all_items, 1):
        print(f"[{i}/{len(all_items)}] Parsing {item_type} {item_id}...")

        result = scraper.parse_item_page(item_id, path, item_type)
        if result:
            item, non_compliant, compliant = result

            # If title wasn't extracted from page, use the one from the nav tree
            if not item.title and title:
                item.title = title

            parsed_items.append(item)

            # Create directory structure: src/rules/cert_c/ARR/ARR30-C/ARR30-C.toml
            rule_dir = Path(args.output) / item.category / item.id
            rule_dir.mkdir(parents=True, exist_ok=True)

            # Generate TOML - filename matches rule ID
            toml_filename = item.id + ".toml"
            toml_path = rule_dir / toml_filename

            # Track state before generation
            is_new = not toml_path.exists()
            existing_date = parse_existing_toml_date(toml_path) if not is_new else None

            generate_toml_metadata(item, toml_path, force=args.force)

            # Track results
            if is_new:
                new_items.append(item_id)
                print(f"  ✓ Generated new TOML: {toml_path}")
            elif args.force:
                updated_items.append(item_id)
                print(f"  ✓ Force updated TOML: {toml_path}")
            elif existing_date and item.last_modified and compare_dates(item.last_modified, existing_date) > 0:
                updated_items.append(item_id)
                print(f"  ✓ Updated TOML: {toml_path}")
            else:
                skipped_items.append(item_id)

            # Save code examples as test files (always update these)
            if non_compliant or compliant:
                save_code_examples(item.id, item.category, non_compliant, compliant, args.output)
        else:
            print(f"  ✗ Failed to parse {item_id}")

    print()
    print("=" * 60)
    print("✅ SCRAPING COMPLETE!")
    print("=" * 60)
    print(f"Scraped {len(parsed_items)} items")
    print(f"  - New TOML files: {len(new_items)}")
    print(f"  - Updated (wiki newer): {len(updated_items)}")
    print(f"  - Unchanged (skipped): {len(skipped_items)}")

    # Count by type
    rules_count = sum(1 for item in parsed_items if item.item_type == "rule")
    rec_count = sum(1 for item in parsed_items if item.item_type == "recommendation")
    print(f"  - Rules: {rules_count}")
    print(f"  - Recommendations: {rec_count}")

    print(f"Output directory: {args.output}")

    if new_items:
        print()
        print("New rules added:")
        for rule_id in new_items:
            print(f"  - {rule_id}")

    if updated_items:
        print()
        print("Rules updated (wiki content newer):")
        for rule_id in updated_items:
            print(f"  - {rule_id}")

    print()
    print("Next steps:")
    print("1. Review generated TOML files")
    print("2. Run: cargo build  # Regenerates rules-all.toml")
    print("3. Implement rules as needed")


if __name__ == "__main__":
    sys.exit(main() or 0)
