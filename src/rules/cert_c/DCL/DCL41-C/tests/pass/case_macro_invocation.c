/*
 * Rule: DCL41-C
 * Source: sqlite ext/fts5/fts5_tcl.c (task 573)
 * Status: PASS - Should NOT trigger DCL41-C violation
 *
 * CASE(i,str) expands to `case i: assert(...);` -- the invocation is itself
 * the first case label, hidden inside a macro aurora-lint's AST-only parse can't
 * expand. Must not be misread as a plain statement preceding the label.
 */

#include <assert.h>

#define CASE(i, str) \
    case i: assert(str != 0);

int dispatch(int op) {
  switch (op) {
    CASE(0, "first") {
      return 1;
    }
    CASE(1, "second") {
      return 2;
    }
    default:
      return -1;
  }
}
