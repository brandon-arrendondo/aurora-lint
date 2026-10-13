/*
 * Rule: INT34-C
 * Source: regression
 * Status: PASS - a continue in a do loop reaches the condition, which bounds the next trip
 *
 * A `continue` in a `do` body jumps to the condition, not back into the
 * body. Here it leaves `i` at zero, so `while (i)` ends the loop on that
 * path, and every trip that runs the body again starts with `i` non-zero:
 * the count stepped down by one before the shift stays within [0, 3].
 */

unsigned int bits_skipping(unsigned int x, const int *skip) {
    unsigned int i = 4;
    unsigned int r = 0;
    do {
        if (skip[i]) {
            i = 0;
            continue;
        }
        i -= 1;
        r |= x >> i;
    } while (i);
    return r;
}
