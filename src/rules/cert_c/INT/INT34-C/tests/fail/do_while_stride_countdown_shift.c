/*
 * Rule: INT34-C
 * Source: regression
 * Status: FAIL - known precision limit, not a defect in the code below
 *
 * The count steps down by 8 from 32 and the loop stops at 0, so the shift
 * amount is always 24, 16, 8 or 0. Value-range analysis keeps an interval,
 * not a stride: from [1, 32] on the next trip, `i -= 8` may go below zero,
 * which wraps an unsigned count to any value, so the shift is reported.
 * Proving it would take tracking that `i` stays a multiple of 8.
 */

unsigned int bytes(unsigned int x) {
    unsigned int i = 32;
    unsigned int r = 0;
    do {
        i -= 8;
        r |= (x >> i) & 0xFFu;
    } while (i);
    return r;
}
