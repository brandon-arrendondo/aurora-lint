# 0006. Resolve an identifier to its declaration; a name is not a variable

## Status

Accepted

## Context

Three independent rules were found, independently, doing the same wrong
thing: standing in for real semantic resolution with matching on an
identifier's *spelling* rather than resolving what it actually declares.

- **EXP05-C** (aurora_lint 1170): `check_param_list_for_const` and
  `declaration_declares_const_var` asked whether a declarator's *text*
  contained the identifier's name — a substring test, not a scope-aware
  lookup. mbedtls's `aes_test_cfb128_iv` answered for every local `iv`;
  a sibling parameter `c` was answered by a `const` on parameter `a`
  because both were tested only for "text contains 'c'."
- **INT02-C** (aurora_lint 1186, pre-rewrite): the entire real-world output
  came from testing whether the literal string `"unsigned short"` appeared
  *anywhere earlier in the file* — no scope, no declaration lookup, not
  even a check that the flagged expression involves that variable at all.
- **INT16-C** (pre-task-1116): a file-wide name-to-type map that resolved
  491 identifier occurrences to a type ran 119/120 wrong on that map's
  own stated purpose, because a name collides across scopes, shadowing,
  and unrelated declarations sharing a spelling.

Three rules, three files, no shared code between them, the same defect
shape each time: **a name is not a variable.** The same spelling can
appear as a local, a parameter, a global, a struct member, a macro
parameter, an unrelated identifier in a comment or string, or a
completely different declaration in another scope — and only resolving the
actual declaration at the specific occurrence distinguishes them.

### The same defect one level up: a tag is not a type

The three instances above are all *rule-local* name matching, and they look
wrong on sight. The harder case is the same mistake made through shared
infrastructure that looks authoritative.

The prescan's `ProjectContext` maps — `struct_field_types`, `typedef_types` —
are keyed by **name across the whole repository**: one entry per struct tag,
one per typedef alias, for every translation unit merged together. C
guarantees nothing of the sort. Two translation units may define entirely
different types under the same tag, and each is correct in its own file.

Found in INT02-C (aurora_lint 1213, item 3), which merged the project map
over the file's own definitions and let the project entry win. curl defines
two different `struct h3_stream_ctx`, one per QUIC backend, whose `id` field
is `uint64_t` in the quiche one and `int64_t` in the ngtcp2 one. The ngtcp2
definition answered for the quiche file, and the rule reported a
signed/unsigned comparison between two `uint64_t` operands — a finding
describing code that does not exist, which is exactly a misfire (ADR-0005).

So: **the definition in the file being scanned wins.** The project map is the
fallback for a tag or alias this file only receives through a header, which
the collector cannot see because headers are not expanded when a file is
parsed. A rule that merges these maps and lets the project side win has
reintroduced the name-is-a-variable bug with a more respectable-looking
source.

Worth noting how it surfaced: not from a count, which looked entirely
plausible, but from reading the individual findings against the source. A
by-name map produces confident, well-formed, wrong answers — there is no
volume signature to notice.

## Decision

When a rule needs to know something about what an identifier occurrence
refers to — its type, its qualifiers (`const`, `restrict`), whether it's a
parameter vs. a local, whatever the rule needs — resolve the occurrence to
its declaration. Never substitute a text/name match (`text.contains(name)`,
"this spelling appeared earlier in the file," a file-wide name→fact map
built without scope) for that resolution, even as a quick first pass.

The same applies to a *type* a rule looks up by name. When consuming the
prescan's by-name maps, the definition in the file being scanned takes
precedence over the project-wide entry; the project map answers only for
names the file does not define itself.

If resolution is uncertain or the primitive to do it properly doesn't
exist yet for the shape at hand, the correct behavior is to **report
nothing for that occurrence**, not to fall back to a name-shaped guess. A
rule that stays silent on what it can't resolve is honest about its
current recall; a rule that guesses from spelling produces findings that
don't describe what's actually on the line — see ADR-0005, this is
precisely how a misfire is made.

The primitives already exist and are cataloged — this is a "use it, don't
reinvent a name match" problem, not a missing-capability problem:
`resolve_identifier_declarator` (used to fix INT16-C and INT02-C's
rewrite), `resolve_field_expression_type`, `resolve_typedef_chain` /
`typedef_chain_is_unsigned`. Check
`docs/design/internal-capability-catalog.md` before writing a new
text/name heuristic, per the existing rule-implementation instruction —
this ADR is the *why* behind that instruction's insistence, backed by
three independent, costly instances of skipping it.

## Consequences

- A code review or rule-bug report that finds `.contains(name)`,
  `lines_before.contains(...)`, or any file-wide name→fact table being
  used to answer "what does this occurrence refer to" is very likely
  looking at a misfire generator, not a tuning question — treat it with
  the urgency ADR-0005 assigns misfires.
- New rules should reach for `resolve_identifier_declarator` and its
  neighbors from the start rather than a quick name check "for now" — all
  three instances here started as a plausible-looking shortcut and became
  a real bug that shipped for a long time before being caught.
- Any rule consuming a prescan by-name map — `struct_field_types`,
  `typedef_types`, and similarly-shaped tables — has the tag-is-not-a-type
  exposure, not just the one where it was found. If a rule merges such a map
  with the current file's own definitions, check which side wins: the file's
  must, with the project map only a fallback for a name reached purely
  through an included header.
- This doesn't mean every rule needs full type inference before it can
  ship — it means the honest fallback for "I can't resolve this
  occurrence" is silence, not a guess keyed on spelling.
- Credit: pattern identified by dev-180 across EXP05-C, INT02-C, and
  INT16-C in the same session that produced ADR-0001/0002; the tag-level
  extension came out of INT02-C's recall work (1213) in the same session.
