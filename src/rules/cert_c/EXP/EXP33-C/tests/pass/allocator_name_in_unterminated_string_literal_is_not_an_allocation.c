/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger EXP33-C violation
 *
 * Malformed: the string literal is never closed. What the parser recovers is
 * still no call to an allocator, so the pointer is not an allocation.
 */

char unterminated(void) {
    const char *p = ")malloc(;
    return p[0];
}
