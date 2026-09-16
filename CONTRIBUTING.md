# Contributing to aurora-lint

aurora-lint is developed at [BISSELL Homecare, Inc.](https://www.bissell.com/)
and maintained by the people listed in
[CONTRIBUTORS.md](CONTRIBUTORS.md). BISSELL funds the maintainers' time and
makes the final call on project direction, the same way any company-backed
open-source project works — but the repository, issue tracker, and pull
requests are open, and community contributions are welcome and reviewed like
any other.

This file covers the rights and process questions around contributing. For
the technical mechanics — adding a CERT C rule, build requirements, dev
environment setup — see the [Developer Guide's Contributing
page](docs/contributing.rst).

## Before you open a PR

- Check open issues and PRs first to avoid duplicate work.
- For anything beyond a small fix, opening an issue to discuss the approach
  first is worth it before investing time in an implementation — especially
  for rule detection-logic changes; several of those questions are already
  settled policy in `docs/adr/`, which is worth a skim first.
- Run `cargo fmt`, `cargo clippy`, and the relevant `cargo test` targets
  locally (see [`docs/contributing.rst`](docs/contributing.rst)). CI runs the
  same checks and won't merge a PR that fails them.

## Developer Certificate of Origin (DCO)

Every commit must carry a `Signed-off-by` trailer certifying you wrote it or
otherwise have the right to submit it under the project's license (the
standard [Developer Certificate of
Origin](https://developercertificate.org/) text). Add it with:

```bash
git commit -s
```

which appends `Signed-off-by: Your Name <your.email@example.com>` using your
git config. Use your real name and a working email — anonymous or pseudonymous
sign-offs aren't accepted.

CI does not yet enforce this automatically; reviewers check for it manually
on each PR until that's wired up.

## Licensing

By submitting a contribution, you agree it's licensed under this project's
license, [Apache-2.0](LICENSE), the same as the rest of the codebase — no
separate CLA is required beyond the DCO sign-off above.

## Commit messages

See CLAUDE.md's "Git Commit Rules" — no `--no-verify`, no AI co-author
trailers (Claude's involvement is acknowledged once, in README's "AI
Assistance" section, not per-commit). A human co-author named normally is
fine.

## Getting help

Open a GitHub issue for questions, bug reports, or feature discussion.
