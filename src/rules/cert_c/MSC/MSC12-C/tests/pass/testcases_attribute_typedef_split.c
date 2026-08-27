/*
 * Rule: MSC12-C
 * Status: PASS - A `typedef` decorated with a trailing unexpandable
 * attribute-style macro (e.g. seL4's `__attribute__((__may_alias__))`)
 * confuses tree-sitter's error recovery into splitting the declaration
 * into a `type_definition` node with a synthesized MISSING ";" plus an
 * orphan expression_statement for the trailing identifier. That tail
 * identifier is not code a human wrote as a standalone statement and
 * must not be flagged as a no-effect bare identifier.
 */

typedef unsigned long __attribute__((__may_alias__)) ulong_alias;

void f(void) {
    ulong_alias v = 0;
    (void)v;
}
