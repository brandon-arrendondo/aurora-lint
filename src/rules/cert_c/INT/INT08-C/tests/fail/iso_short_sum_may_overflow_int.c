/*
 * Rule: INT08-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * ISO C guarantees int only 16 bits. Both shorts promote to int, and
 * 32000 + 1000 = 33000 exceeds a 16-bit INT_MAX: the addition overflows on a
 * conforming target. On a declared LP64 target the same sum is safe (see
 * tests/pass/narrow_promotion_safe.c).
 */

void add(void) {
    short a = 32000;
    short b = 1000;
    int result = a + b; /* VIOLATION */
    (void)result;
}
