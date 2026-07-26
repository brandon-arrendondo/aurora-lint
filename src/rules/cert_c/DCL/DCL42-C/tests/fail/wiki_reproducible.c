/*
 * Rule: DCL42-C
 * Source: wiki
 * Status: FAIL - Should trigger DCL42-C violation
 */

void adjust(unsigned *restrict x, unsigned *restrict y) [[reproducible]] {
    *x -= 3;
    *y += 2;
}