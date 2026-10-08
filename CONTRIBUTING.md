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
- Install the hooks (`pre-commit install`), then run
  `pre-commit run --all-files` and the tests the change needs; the checks
  are listed in the [Repository values](AGENTS.md#repository-values)
  section of the repository guidelines. CI repeats them.

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

The `commit-msg` hook rejects a commit without a valid `Signed-off-by`
trailer, and CI checks the message of every new commit the same way.
`pre-commit install` installs that hook; an older installation may also
need `pre-commit install --hook-type commit-msg`.

## Licensing

By submitting a contribution, you agree it's licensed under this project's
license, [Apache-2.0](LICENSE), the same as the rest of the codebase — no
separate CLA is required beyond the DCO sign-off above.

## Commit messages

Follow the canonical [Git Commit Rules](AGENTS.md#git-commit-rules).

## Getting help

Open a GitHub issue for questions, bug reports, or feature discussion.
