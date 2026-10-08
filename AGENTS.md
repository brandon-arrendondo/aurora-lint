# Repository Guidelines

## Shared agent guidelines

Read the technical guide named in the repository values before changing code.
Follow its architecture, testing, and documentation rules. Keep this shared
section identical across repositories; vary only the repository values.

### Git Commit Rules

Run the repository's applicable checks before committing. If a hook fails,
fix the cause and run it again. Never bypass hooks with `git commit
--no-verify`, `-n`, disabled hook paths, or an equivalent workaround. Do not
skip other commit checks or signing requirements.

Follow the AI-attribution policy in the repository values. Keep attribution
truthful: when a trailer is required, name the agent and vendor that assisted
the commit. Do not change disclosure wording without maintainer review.

When DCO applies, use `git commit -s` with the authorized sign-off identity
in the repository values. Confirm that Git is configured for that identity;
do not invent an identity or sign for someone without their authorization.

Keep task IDs out of public documentation, source comments, and fixtures.
Explain the change and its rationale directly. Commit messages may contain
project-qualified task IDs for internal tracing. Keep credentials, private
fleet details, and locations of unlanded upstream defects out of public files.

Keep these rules in `AGENTS.md`. Agent-specific instruction files import or
link to this file; contributor documentation links here for human readers.
Do not maintain independent copies of this policy.

## Repository values

- **Technical guide:** [CLAUDE.md](CLAUDE.md), including the ADR index and build instructions.
- **AI attribution:** no AI co-author trailers (any agent), or other AI attribution trailers. AI use is acknowledged once in README's "AI Assistance" section; repeating it per commit crowds out the message. Keep that acknowledgement. `sqc_paper` deliberately keeps AI trailers: do not copy this hook there.
- **DCO:** required. The maintainer has authorized agents to use Brandon Arrendondo's configured Git identity as the responsible sign-off party.
- **Checks:** `pre-commit run --all-files` and the relevant tests in the technical guide. Install both hook types with `pre-commit install`; older installations may need `pre-commit install --hook-type commit-msg`.
- **Enforcement:** `scripts/check_commit_message.py` rejects parsed Git trailers naming a listed AI tool/vendor, including human addresses at `openai.com` or `anthropic.com`. Ordinary body prose remains allowed. `.claude/settings.json` denies hook-bypassing commits. The Codex equivalent is `.codex/hooks.json` with a `PreToolUse` command guard; review and trust it with `/hooks` before relying on it. These guards cover ordinary shell commands, not arbitrary programs that invoke Git. CI repeats the hooks, validates new commit messages, and runs guard tests; the maintainer must require those checks before merging.
