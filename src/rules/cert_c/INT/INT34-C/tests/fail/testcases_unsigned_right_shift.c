/*
 * Rule: INT34-C
 * Source: testcases
 * Status: FAIL - Should trigger INT34-C violation. Unsigned right-shift is
 * NOT automatically safe: the shift count being negative or >= the
 * operand's bit width is undefined behavior regardless of direction or
 * signedness (C11 6.5.7p3), and none of these shift amounts are bounded.
 * Previously mislabeled PASS on the mistaken premise that right-shift on
 * unsigned types needs no validation.
 */

unsigned int right_shift_basic(unsigned int val, unsigned int amt) {
    return val >> amt;
}

/* Multiple unsigned params with natural names */
unsigned int right_shift_mask(unsigned int data, unsigned int shift) {
    return data >> shift;
}

/* Unsigned long variant */
unsigned long right_shift_long(unsigned long value, unsigned int bits) {
    return value >> bits;
}
