/*
 * Rule: INT34-C
 * Status: FAIL - Should trigger INT34-C violation. Unsigned right-shift is
 * NOT automatically safe: the shift COUNT being negative or >= the
 * operand's bit width is undefined behavior regardless of direction or
 * signedness (C11 6.5.7p3), and `shift` here is unbounded. Verified
 * against CERT's own "Compliant Solution (Right Shift)" example, which
 * adds a PRECISION()-style bound check to an identical unsigned `>>`.
 * Previously mislabeled PASS on the mistaken premise that right-shift on
 * unsigned types needs no validation.
 */

void f(unsigned int val, unsigned int shift) {
    unsigned int result = val >> shift;
}
