#!/usr/bin/env python3
"""
Scrape SEI CERT C Coding Standard from Confluence Wiki.

This script:
1. Fetches all rule and recommendation categories from the main wiki page
2. Extracts individual items (rules/recommendations) from each category
3. Parses each page for content and metadata
4. Generates TOML metadata files (preserving existing files)
5. Implements rate limiting to be respectful of the wiki

Usage:
    python3 scripts/scrape_cert_wiki.py [--delay SECONDS] [--output DIR] [--type rule|rec|all] [--force]
"""

import re
import os
import sys
import time
import json
import argparse
import requests
import textwrap
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from urllib.parse import urljoin, quote
from bs4 import BeautifulSoup
from datetime import datetime

# Configuration
BASE_URL = "https://wiki.sei.cmu.edu"
WIKI_BASE = f"{BASE_URL}/confluence/display/c"
DEFAULT_DELAY = 3.0  # Seconds between requests (conservative - no robots.txt found)
USER_AGENT = "CERT-C-Scraper/1.0 (Educational Purpose)"

# Output configuration - directly to src/rules/cert_c/
BASE_OUTPUT_DIR = "src/rules/cert_c"

# Category mapping - will be populated dynamically from wiki
# Format: {"CAT": ("number", "Category Name")}
CATEGORIES = {}


@dataclass
class ItemMetadata:
    """Structured metadata for a rule or recommendation from wiki"""
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
    cert_version: Optional[str] = None  # CERT C standard version from wiki
    last_modified: Optional[str] = None  # Last modified date from wiki
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


class WikiScraper:
    """Scraper for CERT C Confluence wiki"""

    def __init__(self, delay: float = DEFAULT_DELAY):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
        self.delay = delay
        self.last_request_time = 0

    def _rate_limit(self):
        """Implement rate limiting between requests"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_request_time = time.time()

    def fetch_page(self, url: str) -> Optional[BeautifulSoup]:
        """Fetch and parse a wiki page with rate limiting"""
        self._rate_limit()

        try:
            print(f"  Fetching: {url}")
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return BeautifulSoup(response.content, 'html.parser')
        except requests.RequestException as e:
            print(f"  ✗ Error fetching {url}: {e}")
            return None

    def discover_categories(self) -> Dict[str, Tuple[str, str]]:
        """
        Dynamically discover all categories from the main wiki page.

        Returns: Dict mapping category code to (number, name)
        Example: {"ARR": ("06", "Arrays"), "MSC": ("48", "Miscellaneous")}
        """
        print("Discovering categories from main wiki page...")
        soup = self.fetch_page(WIKI_BASE)
        if not soup:
            print("  ✗ Failed to fetch main wiki page, using empty categories")
            return {}

        categories = {}

        # Find all links that match "Rule XX" or "Rec. XX" patterns
        # Pattern: "Rule 01. Preprocessor (PRE)" or "Rec. 01. Preprocessor (PRE)"
        for link in soup.find_all('a', href=True):
            link_text = link.get_text(strip=True)

            # Match patterns like:
            # "Rule 06. Arrays (ARR)"
            # "Rec. 48. Miscellaneous (MSC)"
            match = re.match(r'(?:Rule|Rec\.)\s+(\d+)\.\s+([^(]+)\s+\((\w+)\)', link_text)
            if match:
                cat_num, cat_name, cat_code = match.groups()
                cat_name = cat_name.strip()

                # Only add if we haven't seen this category code yet
                # (rules and recommendations might both list it)
                if cat_code not in categories:
                    categories[cat_code] = (cat_num, cat_name)
                    print(f"  Found category: {cat_code} = {cat_num}. {cat_name}")

        print(f"✓ Discovered {len(categories)} categories")
        return categories

    def get_category_items(self, category_code: str, item_type: str) -> List[Tuple[str, str, str]]:
        """
        Get all items (rules or recommendations) from a category page.

        Args:
            category_code: Category code (e.g., "ARR", "MEM")
            item_type: Either "rule" or "recommendation"

        Returns: List of (item_id, item_title, item_url) tuples
        """
        cat_num, cat_name = CATEGORIES[category_code]

        # Build URL based on type
        if item_type == "rule":
            prefix = "Rule"
        else:
            prefix = "Rec."

        # URL format: Rule+06.+Arrays+(ARR)
        cat_url = f"{WIKI_BASE}/{prefix}+{cat_num}.+{cat_name.replace(' ', '+')}+({category_code})"

        soup = self.fetch_page(cat_url)
        if not soup:
            return []

        items = []
        # Find all links that match item pattern: XXX##-C
        item_pattern = re.compile(rf'^{category_code}\d{{2}}-C')

        for link in soup.find_all('a', href=True):
            text = link.get_text(strip=True)
            if item_pattern.match(text):
                # Extract item ID from link text
                match = re.match(rf'({category_code}\d{{2}}-C)', text)
                if match:
                    item_id = match.group(1)
                    # Get the full title (may be in following text)
                    title = text[len(item_id):].strip('. ')

                    # Construct full URL
                    href = link['href']
                    if href.startswith('/'):
                        item_url = urljoin(BASE_URL, href)
                    else:
                        item_url = href

                    items.append((item_id, title, item_url))
                    print(f"    Found: {item_id} - {title}")

        return items

    def parse_item_page(self, item_id: str, item_url: str, item_type: str) -> Optional[Tuple[ItemMetadata, List[str], List[str]]]:
        """
        Parse an individual rule or recommendation page for all content.

        Returns: (ItemMetadata, non_compliant_examples, compliant_examples) or None on error
        """
        soup = self.fetch_page(item_url)
        if not soup:
            return None

        # Extract category and number from item ID
        match = re.match(r'^([A-Z]{3})(\d{2})-C$', item_id)
        if not match:
            return None
        category, number = match.groups()

        # Initialize metadata
        item = ItemMetadata(
            id=item_id,
            item_type=item_type,
            category=category,
            number=int(number),
            title="",
            wiki_url=item_url
        )

        self._extract_title(soup, item_id, item)
        self._extract_last_modified(soup, item)

        # cert_version will be added in the future once source is identified
        # For now, using baseline reference from main wiki page
        item.cert_version = "2016 Edition (Wiki)"

        # Extract main content
        content = soup.find('div', id='main-content')
        if not content:
            return (item, [], [])

        self._extract_description(content, item)
        self._extract_risk_assessment(content, item)
        self._extract_cwe_refs(content, item)
        self._extract_related_items(content, item_id, item)

        # Extract code examples
        non_compliant, compliant = extract_code_examples(content, item_id)

        return (item, non_compliant, compliant)

    def _extract_title(self, soup, item_id: str, item: ItemMetadata) -> None:
        """Extract the page title, stripping the leading item-ID prefix."""
        title_elem = soup.find('h1', id='title-text')
        if title_elem:
            title_text = title_elem.get_text(strip=True)
            item.title = re.sub(rf'^{item_id}\.?\s*', '', title_text)

    def _extract_last_modified(self, soup, item: ItemMetadata) -> None:
        """Extract the last-modified date from the page footer or metadata banner."""
        # Pattern: "last modified by [User] on [Month DD, YYYY]"
        full_text = soup.get_text()
        modified_match = re.search(r'last\s+modified\s+by\s+[^\n]+\s+on\s+([A-Z][a-z]+\s+\d{1,2},\s+\d{4})', full_text, re.IGNORECASE)
        if modified_match:
            item.last_modified = modified_match.group(1)
            return

        # Try alternate format in metadata banner
        page_meta = soup.find('div', id='page-metadata-banner') or soup.find('div', class_='page-metadata')
        if not page_meta:
            return
        meta_text = page_meta.get_text()
        modified_match = re.search(r'(?:Last\s+Modified|Updated):\s*([A-Za-z]+\s+\d{1,2},\s+\d{4})', meta_text, re.IGNORECASE)
        if modified_match:
            item.last_modified = modified_match.group(1)

    def _extract_description(self, content, item: ItemMetadata) -> None:
        """Extract the description from the first few top-level paragraphs/divs."""
        desc_parts = []
        for elem in content.find_all(['p', 'div'], recursive=False):
            text = elem.get_text(strip=True)
            if text and not text.startswith('Rule') and not text.startswith('Rec'):
                desc_parts.append(text)
                if len(desc_parts) >= 3:  # Get first few paragraphs
                    break
        item.description = '\n\n'.join(desc_parts)

    def _extract_risk_assessment(self, content, item: ItemMetadata) -> None:
        """Extract severity/likelihood/priority/level from the risk assessment table."""
        for table in content.find_all('table'):
            headers = [th.get_text(strip=True).lower() for th in table.find_all('th')]
            if 'severity' not in headers and 'likelihood' not in headers:
                continue
            rows = table.find_all('tr')
            if len(rows) <= 1:
                continue
            cells = rows[1].find_all(['td', 'th'])
            for i, header in enumerate(headers):
                if i >= len(cells):
                    continue
                value = cells[i].get_text(strip=True)
                if header == 'severity':
                    item.severity = value
                elif header == 'likelihood':
                    item.likelihood = value
                elif header == 'priority':
                    item.priority = value
                elif header == 'level':
                    item.level = value

    def _extract_cwe_refs(self, content, item: ItemMetadata) -> None:
        """Extract referenced CWE IDs from the page content."""
        cwe_pattern = re.compile(r'CWE-(\d+)')
        for match in cwe_pattern.finditer(str(content)):
            cwe_id = f"CWE-{match.group(1)}"
            if cwe_id not in item.cwe:
                item.cwe.append(cwe_id)

    def _extract_related_items(self, content, item_id: str, item: ItemMetadata) -> None:
        """Extract related rule/recommendation IDs from the first 'Related' section."""
        rule_pattern = re.compile(r'\b([A-Z]{3}\d{2}-C)\b')

        # Look for "Related" section (check multiple possible headings)
        for heading in content.find_all(['h2', 'h3', 'h4']):
            heading_text = heading.get_text(strip=True)
            if 'related' not in heading_text.lower():
                continue
            # Get the next section after this heading
            next_section = heading.find_next_sibling()
            if next_section:
                self._collect_related_ids(next_section.get_text(), item_id, item, rule_pattern)
            break  # Only process first "Related" section

    def _collect_related_ids(self, section_text: str, item_id: str, item: ItemMetadata,
                             rule_pattern: re.Pattern) -> None:
        """Classify each rule-ID match in a 'Related' section as a rule or
        recommendation based on numbering convention and surrounding context.
        """
        for match in rule_pattern.finditer(section_text):
            related_id = match.group(1)
            if related_id == item_id:
                continue

            # Try to determine if it's a rule or recommendation
            # Rules typically have higher numbers (30+), recommendations lower (00-29)
            related_num = int(related_id[3:5])

            # Also check context around the match
            start = max(0, match.start() - 50)
            end = min(len(section_text), match.end() + 50)
            context = section_text[start:end].lower()

            if 'recommendation' in context or related_num < 30:
                if related_id not in item.related_recommendations:
                    item.related_recommendations.append(related_id)
            else:
                if related_id not in item.related_rules:
                    item.related_rules.append(related_id)


def sanitize_code(code: str) -> str:
    """
    Clean invisible/non-printable characters from code.
    Removes non-breaking spaces, zero-width spaces, etc.
    """
    # Replace non-breaking space (U+00A0) with regular space
    code = code.replace('\u00a0', ' ')
    # Replace zero-width space (U+200B)
    code = code.replace('\u200b', '')
    # Replace zero-width non-joiner (U+200C)
    code = code.replace('\u200c', '')
    # Replace zero-width joiner (U+200D)
    code = code.replace('\u200d', '')
    # Replace other common invisible characters
    code = code.replace('\ufeff', '')  # Zero-width no-break space (BOM)
    return code


def extract_code_examples(content, item_id: str) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """
    Extract compliant and non-compliant code examples from page content.

    Returns: (non_compliant_examples, compliant_examples)
    Each tuple is (example_name, code)
    """
    non_compliant = []
    compliant = []

    # Find all headings and their code blocks
    for heading in content.find_all(['h2', 'h3', 'h4', 'h5']):
        heading_text = heading.get_text(strip=True)
        heading_lower = heading_text.lower()

        # Create a clean filename from heading (remove "Noncompliant Code Example", etc.)
        clean_name = heading_text
        for remove_phrase in ['Noncompliant Code Example', 'Compliant Solution', 'Non-Compliant Code Example']:
            clean_name = re.sub(re.escape(remove_phrase), '', clean_name, flags=re.IGNORECASE)
        clean_name = clean_name.strip(' :-')

        # If no descriptive name, use generic counter
        if not clean_name or len(clean_name) < 3:
            clean_name = None

        # Check if this is a non-compliant example
        if 'noncompliant' in heading_lower or 'non-compliant' in heading_lower:
            # Find all code blocks after this heading until next heading
            current = heading.find_next_sibling()
            code_count = 0
            while current and current.name not in ['h2', 'h3', 'h4', 'h5']:
                if current.name == 'pre' or (current.name == 'div' and 'code' in current.get('class', [])):
                    code = current.get_text()
                    code = sanitize_code(code)  # Clean invisible characters
                    if code.strip():
                        code_count += 1
                        if clean_name:
                            example_name = sanitize_filename(clean_name)
                        else:
                            example_name = f"noncompliant_{len(non_compliant) + 1}"

                        # If multiple code blocks under same heading, add suffix
                        if code_count > 1:
                            example_name = f"{example_name}_{code_count}"

                        non_compliant.append((example_name, code.strip()))
                current = current.find_next_sibling()

        # Check if this is a compliant example
        elif 'compliant' in heading_lower and 'non' not in heading_lower:
            # Find all code blocks after this heading until next heading
            current = heading.find_next_sibling()
            code_count = 0
            while current and current.name not in ['h2', 'h3', 'h4', 'h5']:
                if current.name == 'pre' or (current.name == 'div' and 'code' in current.get('class', [])):
                    code = current.get_text()
                    code = sanitize_code(code)  # Clean invisible characters
                    if code.strip():
                        code_count += 1
                        if clean_name:
                            example_name = sanitize_filename(clean_name)
                        else:
                            example_name = f"compliant_{len(compliant) + 1}"

                        # If multiple code blocks under same heading, add suffix
                        if code_count > 1:
                            example_name = f"{example_name}_{code_count}"

                        compliant.append((example_name, code.strip()))
                current = current.find_next_sibling()

    return non_compliant, compliant


def sanitize_filename(name: str) -> str:
    """Convert heading text to valid filename"""
    # Replace special characters with underscores
    name = re.sub(r'[^\w\s-]', '', name)
    name = re.sub(r'[-\s]+', '_', name)
    name = name.strip('_')
    name = name.lower()
    # Limit length
    if len(name) > 60:
        name = name[:60]
    return name


def save_code_examples(item_id: str, category: str, non_compliant: List[Tuple[str, str]], compliant: List[Tuple[str, str]], output_dir: str):
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

        # Add header comment
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

        # Add header comment
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
    text = text.replace('\xa0', ' ')

    paragraphs = text.split('\n\n')
    wrapped_paragraphs = []

    for para in paragraphs:
        # Remove existing line breaks within paragraph
        para = ' '.join(para.split())
        # Wrap to width
        wrapped = textwrap.fill(para, width=width)
        wrapped_paragraphs.append(wrapped)

    return '\n'.join(wrapped_paragraphs)


def parse_existing_toml_date(toml_path: Path) -> Optional[str]:
    """Extract last_modified date from existing TOML file"""
    try:
        with open(toml_path, 'r') as f:
            content = f.read()
            # Look for last_modified = "..." line
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
    except:
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
    toml_lines.append(f'number = {item.number}')
    toml_lines.append(f'title = {toml_inline_string(item.title)}')

    # Description with multi-line string (literal-string-encoded so scraped
    # backslashes/quotes can't produce invalid TOML — see task 200).
    if wrapped_desc:
        toml_lines.append('description = ' + toml_multiline_string(wrapped_desc))
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
    toml_lines.append(f'[rules.cert_c.{item.id}]')
    toml_lines.append('enabled = false')
    toml_lines.append("")

    # References section
    toml_lines.append("[references]")
    toml_lines.append(f'wiki = "{item.wiki_url}"')

    if item.cwe:
        cwe_list = ', '.join([f'"{cwe}"' for cwe in item.cwe])
        toml_lines.append(f'cwe = [{cwe_list}]')
    else:
        toml_lines.append('cwe = []')

    toml_lines.append("")

    # Write to file
    with open(output_path, 'w') as f:
        f.write('\n'.join(toml_lines))


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Scrape CERT C wiki and generate TOML metadata')
    parser.add_argument('--delay', type=float, default=DEFAULT_DELAY,
                        help=f'Delay between requests in seconds (default: {DEFAULT_DELAY})')
    parser.add_argument('--output', type=str, default=BASE_OUTPUT_DIR,
                        help=f'Output base directory (default: {BASE_OUTPUT_DIR})')
    parser.add_argument('--categories', type=str, nargs='+',
                        help='Specific categories to scrape (e.g., ARR MEM), default: all')
    parser.add_argument('--type', choices=['rule', 'rec', 'all'], default='all',
                        help='Scrape rules, recommendations, or both (default: all)')
    parser.add_argument('--force', action='store_true',
                        help='Force overwrite existing TOML files')
    args = parser.parse_args()

    print("=" * 60)
    print("CERT C Wiki Scraper - TOML Generation")
    print("=" * 60)
    print(f"Rate limit: {args.delay}s between requests")
    print(f"  (Note: No robots.txt found - using conservative default)")
    print(f"Output directory: {args.output}")
    print(f"Scraping: {args.type}")
    print(f"Force overwrite: {args.force}")
    print()

    # Create scraper
    scraper = WikiScraper(delay=args.delay)

    # Discover categories dynamically from wiki
    global CATEGORIES
    CATEGORIES = scraper.discover_categories()
    print()

    if not CATEGORIES:
        print("✗ No categories discovered from wiki. Exiting.")
        return 1

    # Determine which categories to scrape
    categories_to_scrape = args.categories if args.categories else CATEGORIES.keys()

    # Determine what types to scrape
    types_to_scrape = []
    if args.type in ['rule', 'all']:
        types_to_scrape.append('rule')
    if args.type in ['rec', 'all']:
        types_to_scrape.append('recommendation')

    # Collect all items
    all_items = []

    for item_type in types_to_scrape:
        print(f"\n{'='*60}")
        print(f"Collecting {item_type.upper()}S from category pages...")
        print(f"{'='*60}")

        for category_code in categories_to_scrape:
            if category_code not in CATEGORIES:
                print(f"  ✗ Unknown category: {category_code}")
                continue

            print(f"\n[{category_code}] Fetching {item_type} category page...")
            items = scraper.get_category_items(category_code, item_type)
            print(f"  ✓ Found {len(items)} {item_type}s")
            all_items.extend([(item_type, category_code, item_id, title, url)
                            for item_id, title, url in items])

    print(f"\n✓ Total items found: {len(all_items)}")
    print()

    # Parse each item
    print("=" * 60)
    print("Parsing individual pages and generating TOML...")
    print("=" * 60)
    parsed_items = []
    skipped_items = []
    new_items = []
    updated_items = []

    for i, (item_type, category, item_id, title, url) in enumerate(all_items, 1):
        print(f"[{i}/{len(all_items)}] Parsing {item_type} {item_id}...")

        result = scraper.parse_item_page(item_id, url, item_type)
        if result:
            item, non_compliant, compliant = result

            # If title wasn't extracted from page, use the one from category page
            if not item.title and title:
                item.title = title

            parsed_items.append(item)

            # Create directory structure: src/rules/cert_c/ARR/ARR30-C/ARR30-C.toml
            rule_dir = Path(args.output) / item.category / item.id
            rule_dir.mkdir(parents=True, exist_ok=True)

            # Generate TOML - filename matches rule ID
            toml_filename = item.id + '.toml'
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
    main()
