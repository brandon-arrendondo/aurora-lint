/*
 * Rule: EXP43-C
 * Source: task 411 regression
 * Status: PASS - Should NOT trigger EXP43-C violation
 *
 * f() assigns its local `q` from its local `w` (q -> w in a whole-file
 * pointer_bases map). g() reuses the same parameter names `q` and `w` for two
 * genuinely independent, unrelated pointers. Without per-function scoping of
 * the pointer-base tracking map, g()'s strcpy(q, w) call resolves `q` through
 * f()'s leftover q->w mapping, making it look identical to `w` and firing a
 * false "aliased pointers" violation even though g()'s q and w have no
 * relationship to each other or to f() at all.
 */
#include <string.h>

void f(void) {
  char *w;
  char *q = w;
  (void)q;
}

void g(char *q, char *w) {
  strcpy(q, w);
}
