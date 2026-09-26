/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: EXPECTED FAIL - a known limitation (see below)
 *
 * Reaching past `if (p == 0 && x) return;` says only that the condition was
 * false: `p != 0 || !x`. With `x` false, `p` may still be null, so the
 * dereference after it is unguarded. Only a guard whose every conjunct is
 * the null test proves anything here.
 *
 * The condition analysis no longer credits this guard (De Morgan: a false
 * `A && B` proves only `!A || !B`), but is_dominated_by_null_check still
 * treats any earlier `if (p == 0 ...)` as a guard, whatever it does. That
 * heuristic is a separate, already-ruled fix; this fixture moves to fail/
 * when it lands.
 */
#include <stdlib.h>

struct L { int b; };

int after_conjunction_guard(int x) {
    struct L *p = malloc(sizeof *p);
    if (p == 0 && x) {
        return 1;
    }
    return p->b;
}
