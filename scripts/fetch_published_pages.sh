#!/usr/bin/env bash
# Extract the published GitHub Pages site (the gh-pages branch) into DIR, for
# scripts/assemble_pages_site.py to build the next deploy from.
#
# Before the first deploy there is no gh-pages branch, and DIR is left empty.
# Any other failure to reach the branch stops the deploy: publishing without
# the current site would delete every release's docs from it.
#
# Usage: scripts/fetch_published_pages.sh DIR
set -euo pipefail

dir=${1:?usage: fetch_published_pages.sh DIR}
mkdir -p "$dir"

set +e
git ls-remote --exit-code --heads origin gh-pages >/dev/null
rc=$?
set -e

case $rc in
  0)
    git fetch --depth 1 origin gh-pages
    git archive FETCH_HEAD | tar -x -C "$dir"
    echo "fetched gh-pages $(git rev-parse --short FETCH_HEAD) into $dir"
    ;;
  2)
    echo "no gh-pages branch yet; $dir is empty"
    ;;
  *)
    echo "fetch_published_pages: cannot read origin's branches (git ls-remote exit $rc)" >&2
    exit "$rc"
    ;;
esac
