/*
 * Rule: INT30-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * `0x3u` and `1U` fit the 16 bits ISO C guarantees unsigned int, so the shifts
 * and the sum are unsigned int arithmetic and wrap there. On a declared target
 * with a 32-bit unsigned int the shifts fit (tests/pass).
 */

void widths(unsigned value) {
    value = 0x3u << 16; /* VIOLATION */
    value = 1U << 31; /* VIOLATION */
    value = 40000u + 40000u; /* VIOLATION */
}
