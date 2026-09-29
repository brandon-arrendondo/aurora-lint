#!/usr/bin/env python3
"""Assemble the GitHub Pages site: main's docs at the root, each release's
docs under /<tag>/, kept for good.

Papers pin a release and cite its docs pages. The raw .rst shows
`|rules_total|` rather than the number, so a citation needs the rendered page
for that tag, at a URL no later deploy changes. The Pages deploy replaces the
whole gh-pages branch, which would delete a tag's pages on the next push to
main, so both deploys build the complete site here and publish it whole:

- ``main``: the new main build at the root, plus every release directory
  already published, copied through unchanged.
- ``tag``: the site as published, plus the tag's build under /<tag>/. A tag
  already published is refused: its pages have been cited, and a rebuild
  (under a newer Sphinx, say) would change them.

Either way the site root gets a ``versions.html`` listing every release, and
the new build is refused if a substitution from docs/conf.py's rst_epilog
reached its HTML unresolved. Sphinx's own build state (``.doctrees``,
``.buildinfo``) is left out, so it is not frozen into a release directory.

``missing`` prints a GitHub Actions warning for each TAG with no directory
in the published site, and always exits 0. A tag's docs job can be cancelled
without a trace (a newer deploy in the same concurrency group replaces a
pending one), so main's deploy runs this to make a lost release visible.

Usage:
    python3 scripts/assemble_pages_site.py main BUILD PUBLISHED OUT
    python3 scripts/assemble_pages_site.py tag TAG BUILD PUBLISHED OUT
    python3 scripts/assemble_pages_site.py missing PUBLISHED [TAG...]

BUILD is the fresh ``sphinx-build -b html`` output, PUBLISHED the current
gh-pages tree (an empty directory before the first deploy) and OUT a
directory that must not exist yet. Exit 1 with a message on any refusal.
"""
import html
import re
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# A release tag, vMAJOR.MINOR.PATCH with an optional -PRE of dot-separated
# alphanumeric identifiers (v1.0.0-rc.1), as a directory name at the site
# root. Anything else at the root belongs to main's build.
RELEASE_TAG = re.compile(r"^v\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?$")

# Sphinx's incremental-build state, which is not part of the site.
BUILD_STATE = shutil.ignore_patterns(".doctrees", ".buildinfo")

# A literal block or inline literal, where a page may show `|name|` on purpose.
LITERAL = re.compile(r"<(pre|code)\b.*?</\1>", re.S)


class Refused(Exception):
    """A deploy that would lose or change published pages."""


def epilog_substitutions(conf_py: Path) -> list[str]:
    """Every `|name|` docs/conf.py defines in its rst_epilog."""
    return re.findall(r"^\.\. \|(\w+)\| replace::", conf_py.read_text(), re.M)


def unresolved_substitutions(build: Path, names: list[str]) -> list[str]:
    """`page: |name|` for each substitution left literal in the built HTML's
    prose. Code blocks and inline literals are skipped: they show a `|name|`
    verbatim when a page documents the substitution itself."""
    pattern = re.compile(r"\|(" + "|".join(map(re.escape, names)) + r")\|")
    found = []
    for page in sorted(build.rglob("*.html")):
        prose = LITERAL.sub("", page.read_text(errors="replace"))
        for name in sorted(set(pattern.findall(prose))):
            found.append(f"{page.relative_to(build)}: |{name}|")
    return found


def published_releases(published: Path) -> list[str]:
    """Release directories at the root of the published site."""
    return sorted(
        (p.name for p in published.iterdir() if p.is_dir() and RELEASE_TAG.match(p.name)),
        key=release_sort_key,
        reverse=True,
    )


def release_sort_key(tag: str) -> tuple:
    """Newest first once reversed: numeric on major.minor.patch, and a
    pre-release (v1.0.0-rc1) before its release."""
    core, _, pre = tag[1:].partition("-")
    major, minor, patch = (int(n) for n in core.split(".")[:3])
    return (major, minor, patch, pre == "", pre)


def versions_page(releases: list[str]) -> str:
    """A plain page linking the latest docs and each release's."""
    items = "\n".join(
        f'    <li><a href="{html.escape(t)}/index.html">{html.escape(t)}</a></li>'
        for t in releases
    )
    body = items if releases else "    <li>No release has been published yet.</li>"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>aurora-lint documentation versions</title>
</head>
<body>
  <h1>aurora-lint documentation versions</h1>
  <p><a href="index.html">Latest (main branch)</a></p>
  <p>Each release's documentation, as published when it was tagged:</p>
  <ul>
{body}
  </ul>
</body>
</html>
"""


def check_build(build: Path, conf_py: Path) -> None:
    if not (build / "index.html").is_file():
        raise Refused(f"{build} has no index.html: not a Sphinx HTML build")
    left = unresolved_substitutions(build, epilog_substitutions(conf_py))
    if left:
        raise Refused("unresolved substitutions in the build:\n  " + "\n  ".join(left))


def assemble_main(build: Path, published: Path, out: Path, conf_py: Path) -> list[str]:
    check_build(build, conf_py)
    releases = published_releases(published)
    clash = [t for t in releases if (build / t).exists()]
    if clash:
        raise Refused(f"main's build has a top-level {clash[0]}/, which is a release's path")
    shutil.copytree(build, out, ignore=BUILD_STATE)
    for tag in releases:
        shutil.copytree(published / tag, out / tag)
    (out / "versions.html").write_text(versions_page(releases))
    return releases


def assemble_tag(tag: str, build: Path, published: Path, out: Path, conf_py: Path) -> list[str]:
    if not RELEASE_TAG.match(tag):
        raise Refused(f"{tag!r} is not a release tag (vMAJOR.MINOR.PATCH[-PRE])")
    check_build(build, conf_py)
    if (published / tag).exists():
        raise Refused(f"/{tag}/ is already published; a release's pages are never replaced")
    shutil.copytree(published, out, ignore=shutil.ignore_patterns(".git"))
    shutil.copytree(build, out / tag, ignore=BUILD_STATE)
    releases = published_releases(out)
    (out / "versions.html").write_text(versions_page(releases))
    return releases


def missing_releases(published: Path, tags: list[str]) -> list[str]:
    """The release tags in `tags` with no directory in the published site."""
    return [t for t in tags if RELEASE_TAG.match(t) and not (published / t).is_dir()]


def main(argv: list[str]) -> int:
    conf_py = REPO_ROOT / "docs" / "conf.py"
    if len(argv) >= 2 and argv[0] == "missing":
        for tag in missing_releases(Path(argv[1]), argv[2:]):
            print(f"::warning title=Release docs missing::/{tag}/ is not published; "
                  f"re-run the docs job of the {tag} release workflow")
        return 0
    try:
        if len(argv) == 4 and argv[0] == "main":
            build, published, out = map(Path, argv[1:])
            releases = assemble_main(build, published, out, conf_py)
        elif len(argv) == 5 and argv[0] == "tag":
            tag = argv[1]
            build, published, out = map(Path, argv[2:])
            releases = assemble_tag(tag, build, published, out, conf_py)
        else:
            print(__doc__.split("Usage:")[1].split("BUILD")[0].rstrip(), file=sys.stderr)
            return 2
    except Refused as e:
        print(f"assemble_pages_site: refused: {e}", file=sys.stderr)
        return 1
    print(f"assembled {out}: main at the root, releases: {', '.join(releases) or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
