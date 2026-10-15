/*
 * Rule: INT34-C
 * Status: PASS - Hex and binary literal amounts fold below the precision
 * Settings: data_model=lp64
 *
 * A literal amount is judged by its value. On a declared LP64 target an
 * unsigned int has 32 bits, so 16 and 4 are in range; under ISO C's
 * guaranteed 16 bits, 16 is not.
 */

unsigned int f(unsigned int val) {
    return val << 0x10;  /* 16 in hex - literal shift amount */
}

unsigned int g(unsigned int val) {
    return val >> 0b0100;  /* 4 in binary - literal shift amount */
}

unsigned int h(unsigned int val) {
    return val << 010;  /* 8 in octal - literal shift amount */
}
