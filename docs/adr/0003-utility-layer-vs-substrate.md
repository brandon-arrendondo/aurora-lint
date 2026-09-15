# 0003. New reusable capability defaults to aurora-lint's own utility layer; promote to `lang_parsing_substrate` only when it's genuinely cross-language

## Status

Accepted

## Context

Two layers exist to foster reuse across rules, and it's a recurring question
which one new reusable logic belongs in:

- `lang_parsing_substrate` — a shared crate whose job is general program
  structure *across languages* (call graphs, generic AST query, CFG shape).
  It does know about C specifically at some level — it can answer general,
  API-shaped questions about a C program — but it's deliberately generic. It
  does not, and structurally should not, carry the fine-grained,
  rule-specific knowledge a CERT-C detector needs: the nitty-gritty of C
  semantics that only matters for this ruleset's defect detection.
- aurora-lint's own utility layer (`src/utility/cert_c/*.rs`,
  `src/analyze/*.rs`, catalogued in
  `docs/design/internal-capability-catalog.md`) — C-specific, rule-specific
  primitives: macro expansion mechanics, declarator-chain walking, type
  resolution, and similar.

`docs/design/cfg-substrate-adoption-decision.md` is one instance of this
tension already resolved: the substrate's CFG builder is a strict subset of
aurora-lint's own (no `switch` decomposition, no `goto` wiring, no
macro-constant folding) — real, load-bearing, C-specific rule-detection
behavior that doesn't belong pushed down into a cross-language layer, at
least not without real engineering cost and zero net capability gain.

## Decision

New reusable functionality that doesn't already exist in the capability
catalog defaults to living in aurora-lint's own utility layer
(`src/utility/cert_c/*.rs`, `src/analyze/*.rs`), not the substrate. This is
not a permanent choice — it can be promoted to the substrate later if it
turns out to be genuinely general enough to belong there.

The dividing line: the substrate owns general program-structure questions
that would make sense for a parser of a different language too (call
graphs, generic AST traversal, control-flow shape as a concept).
aurora-lint's utility layer owns C-specific, CERT-C-rule-specific knowledge
that only this ruleset needs and that would be dead weight in a
cross-language crate.

Check the capability catalog and grep the existing layers first, per the
rule-implementation instruction in `CLAUDE.md` — favor not reinventing
something that already exists in either layer. But when something is
genuinely new, build it in utilities unless it's obviously general-purpose
across languages. Don't hold up landing something useful while deciding
whether it "belongs" in the substrate instead.

## Consequences

- A new C-specific AST/text heuristic (e.g. "is this declarator a
  pointer-to-function", "does this macro null a parameter") goes in
  `src/utility/cert_c/` or `src/analyze/`, gets documented in the capability
  catalog, and stays there by default.
- Don't block a utility change on "should this really be in the substrate" —
  that's a separate, later decision, best made once a pattern has actually
  recurred across multiple rules/consumers. See
  `docs/design/cfg-substrate-adoption-decision.md` for what that decision
  looks like once made, including what a real net-capability-gain
  justification (vs. a pure refactor with no gain) has to show.
- If something is promoted to the substrate later, its public API there
  should stay general/cross-language-shaped; C-specific glue and
  interpretation stay on the aurora-lint side of the boundary, calling into
  the substrate primitive.
