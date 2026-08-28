/*
 * Rule: MSC17-C
 * Source: sqlite ext/fts5/fts5_expr.c:2249 (task 634, gpu-node finding)
 * Status: PASS - Should NOT trigger MSC17-C violation
 *
 * `case X: { ...; break; };` -- a stray, pointless trailing semicolon after
 * the closing brace -- parses as its own empty expression_statement sibling
 * *after* the compound_statement, not inside it. Treating that stray `;` as
 * the case section's "last item" hid the real terminator (the `break;`
 * inside the braces), reported as a false fallthrough on 12/126 (10%) of a
 * sample of sqlite's MSC17-C findings.
 */

void f(int op) {
  switch (op) {
  case 1: {
    g();
    break;
  };
  case 2:
    h();
    break;
  }
}
