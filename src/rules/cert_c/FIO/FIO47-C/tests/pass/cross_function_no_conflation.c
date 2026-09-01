/*
 * Rule: FIO47-C
 * Source: task 418 (task-389 sweep, whole-file var_types conflation)
 * Status: PASS - Should NOT trigger FIO47-C violation
 *
 * `var_types` was previously built by a single whole-translation-unit walk
 * with no per-function reset, so `func_a`'s local `float x` leaked into
 * `func_b`'s unrelated `int x` parameter and caused a bogus "expects
 * Integer but argument is Float" type-mismatch report on a perfectly
 * correct `printf("%d", x)` call.
 */
#include <stdio.h>

void func_a(void) {
    float x = 1.0f;
    (void)x;
}

void func_b(int x) {
    printf("%d\n", x);
}
