/*
 * Rule: INT34-C
 * Source: regression
 * Status: PASS - a do loop's condition bounds the shift amount on the next trip
 *
 * `do { ... } while (i)` runs the body again only when `i` is non-zero, as
 * `while (i)` enters it only then, so a count stepped down by one before the
 * shift stays within [0, 3] here. The comparison forms read the same way.
 */

unsigned int bits_while(unsigned int x) {
    unsigned int i = 4;
    unsigned int r = 0;
    do {
        i -= 1;
        r |= x >> i;
    } while (i);
    return r;
}

unsigned int bits_not_zero(unsigned int x) {
    unsigned int i = 4;
    unsigned int r = 0;
    do {
        i -= 1;
        r |= x >> i;
    } while (i != 0);
    return r;
}

unsigned int bits_above_zero(unsigned int x) {
    unsigned int i = 4;
    unsigned int r = 0;
    do {
        i--;
        r |= x >> i;
    } while (i > 0);
    return r;
}
