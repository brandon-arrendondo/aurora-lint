/*
 * Rule: INT34-C
 * Status: FAIL - Should trigger INT34-C violation. Unsigned right-shift is
 * NOT automatically safe: the shift count being negative or >= the
 * operand's bit width is undefined behavior regardless of direction or
 * signedness (C11 6.5.7p3), and none of these shift amounts are bounded.
 * Previously mislabeled PASS on the mistaken premise that right-shift on
 * unsigned types needs no validation.
 */

void param_unsigned_int(unsigned int val, unsigned int n) {
    unsigned int result = val >> n;
}

void param_unsigned_long(unsigned long data, unsigned int shift) {
    unsigned long result = data >> shift;
}

void param_unsigned_short(unsigned short val, unsigned int n) {
    unsigned short result = val >> n;
}

/* Local unsigned variable declarations */
void local_unsigned_var(int n) {
    unsigned int val = 42;
    unsigned int result = val >> n;
}
