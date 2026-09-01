/*
 * Rule: INT08-C
 * Source: task 418 (task-389 sweep, whole-file variables conflation)
 * Status: PASS - Should NOT trigger INT08-C violation
 *
 * `variables` was previously built by a single whole-translation-unit
 * walk with no per-function reset, so `func_a`'s local narrow `char c`
 * leaked into `func_b`'s unrelated `int c` parameter and caused a bogus
 * "narrow type" overflow report on plain `int` arithmetic (which INT08-C
 * deliberately excludes -- int overflow is INT32-C's concern).
 */

void func_a(void) {
    char c;
    c = 'a';
    (void)c;
}

void func_b(int c) {
    int y = c + 1;
    (void)y;
}
