/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * Reaching past `if (p == 0 && x) return;` says only that the condition was
 * false: `p != 0 || !x`. With `x` false, `p` may still be null, so the
 * dereference after it is unguarded. Only a guard whose every conjunct is
 * the null test proves anything here (De Morgan: a false `A && B` proves
 * only `!A || !B`).
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
