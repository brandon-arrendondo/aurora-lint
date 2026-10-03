/*
 * Rule: INT30-C
 * Source: regression
 * Status: PASS - no data model is declared
 *
 * C11 6.4.4.1p5 gives a constant the first type that holds it from the rank
 * its suffix names. `1LU` is at least unsigned long, which ISO C guarantees
 * 32 bits, and a decimal `86400u` is too big for a 16-bit unsigned int, so it
 * is unsigned long: the shift and the product below stay within those widths
 * wherever the code is built.
 */

void consume(unsigned long value);

void widths(unsigned count) {
    (void)count;
    consume(1LU << 25u);
    consume(86400u * 7);
    consume(1UL << 20);
}
