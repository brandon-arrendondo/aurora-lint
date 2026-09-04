/* Rule: INT32-C
 * Source: testcases (task 926)
 * Status: PASS - arithmetic on char/short operands whose result is consumed
 * at int width. The usual arithmetic conversions promote both operands to
 * `int` before the operation runs, and no `+`, `-` or `*` over two promoted
 * narrow operands can leave `int` -- the widest such product,
 * -32768 * -32768, is still under INT_MAX.
 *
 * These fired because the rule checked the result against the *operands'*
 * declared 8 or 16 bits rather than the width the arithmetic actually
 * happens at. Storing the result back into something narrow is a different
 * question and still reported; see tests/fail/narrow_truncating_store.c.
 */

/* char + char, consumed as int. */
int narrow_add(char c, char d) {
    return c + d;
}

/* char - char, consumed as int. */
int narrow_sub(char c, char d) {
    return c - d;
}

/* short * short: peak magnitude 2^30, comfortably inside int. */
int narrow_mul(short s, short t) {
    return s * t;
}

/* Mixed narrow widths, still bounded by the wider operand's promoted range. */
int mixed_narrow(char c, short s) {
    return c * s;
}

/* Result handed to an int-taking consumer rather than stored narrow. */
void narrow_arg(short a, short b, void (*sink)(int)) {
    sink(a + b);
}

/* Explicit widening cast: destination is wider than int, not narrower. */
long narrow_widened(short a, short b) {
    return (long)(a + b);
}

/* Cast to int before the store: the destination named by the cast is int. */
int narrow_cast_to_int(char c, char d) {
    return (int)(c + d);
}
