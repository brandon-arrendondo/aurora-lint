/*
 * Rule: INT15-C
 * Source: task 418 (task-389 sweep, whole-file var_types conflation)
 * Status: PASS - Should NOT trigger INT15-C violation
 *
 * `var_types` was previously built by a single whole-translation-unit walk
 * with no per-function reset, so `func_a`'s local `myint_t x` leaked into
 * `func_b`'s unrelated `int x` parameter and caused a bogus "scanf with
 * programmer-defined type" report on a plain `int` scanf.
 */
#include <stdio.h>

typedef long myint_t;

void func_a(void) {
    myint_t x;
    x = 5;
    (void)x;
}

void func_b(int x) {
    scanf("%d", &x);
}
