/*
 * Rule: DCL42-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

void adjust(unsigned *restrict x, unsigned *restrict y) [[reproducible]] {
    *x &= ~3;
    *y |= 2;
}