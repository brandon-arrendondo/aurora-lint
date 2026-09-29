/*
 * Rule: INT32-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * Both shorts promote to int, which ISO C guarantees only 16 bits: there
 * 300 * 300 = 90000 exceeds INT_MAX. On a declared LP64 target the same
 * product fits (tests/pass/narrow_promotion_safe.c).
 */

int narrow_mul(void) {
    short s = 300;
    short t = 300;
    return s * t; /* VIOLATION */
}
