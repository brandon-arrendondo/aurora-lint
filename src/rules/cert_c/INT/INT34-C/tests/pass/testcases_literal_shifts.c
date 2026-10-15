/*
 * Rule: INT34-C
 * Source: testcases
 * Status: PASS - Literal amounts in every format fold below the precision
 * Settings: data_model=lp64
 *
 * A literal amount is judged by its value, so each format has to fold. On a
 * declared LP64 target an unsigned int has 32 bits, so 16 is in range;
 * under ISO C's guaranteed 16 bits, it is not.
 */

/* Hex literal shift amount */
unsigned int shift_hex(unsigned int x) {
    return x << 0x10;
}

/* Octal literal shift amount */
unsigned int shift_octal(unsigned int x) {
    return x << 010;
}

/* Binary literal shift amount */
unsigned int shift_binary(unsigned int x) {
    return x << 0b1010;
}

/* Literal with unsigned suffix */
unsigned int shift_suffix_u(unsigned int x) {
    return x << 8u;
}

/* Literal with UL suffix */
unsigned int shift_suffix_ul(unsigned int x) {
    return x << 16UL;
}

/* Left shift by zero */
int shift_by_zero(int x) {
    return x << 0;
}

/* Right shift by literal */
int right_shift_literal(int x) {
    return x >> 4;
}
