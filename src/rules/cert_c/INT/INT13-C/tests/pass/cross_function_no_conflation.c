/*
 * Rule: INT13-C
 * Source: task 418 (task-389 sweep, whole-file variables conflation)
 * Status: PASS - Should NOT trigger INT13-C violation
 *
 * `variables` was previously built by a single whole-translation-unit
 * walk with no per-function reset, so `func_a`'s local signed `int mask`
 * leaked into `func_b`'s unrelated `unsigned int mask` parameter and
 * caused a bogus "used on signed operand" report on a perfectly compliant
 * unsigned shift.
 */

void func_a(void) {
    int mask;
    mask = 5;
    (void)mask;
}

void func_b(unsigned int mask) {
    unsigned int y = mask << 2;
    (void)y;
}
