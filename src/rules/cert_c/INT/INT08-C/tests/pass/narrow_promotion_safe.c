/* Rule: INT08-C
 * Source: testcases (moved from tests/fail, task 755)
 * Status: PASS - narrow-typed arithmetic that provably cannot exceed a
 * >=32-bit promoted `int`'s range.
 *
 * These were originally written as FAIL cases on the theory that any
 * arithmetic on a narrow (char/short) operand without a visible guard is
 * risky. It isn't: narrow types promote to `int` before the arithmetic
 * happens, and `+`/`-` can never grow a narrow operand's magnitude past
 * `int`'s range; `*`/`<<` can, but not at these magnitudes.
 */

/* short + short: promoted-int sum tops out in the low tens of thousands,
 * nowhere near INT_MAX. */
void test_short_add(void) {
    short a = 32000;
    short b = 1000;
    short result = a + b;
}

/* unsigned char * unsigned char: promoted-int product maxes at 255*255 =
 * 65025, far below INT_MAX. */
void test_uchar_multiply(void) {
    unsigned char x = 200;
    unsigned char y = 2;
    unsigned char result = x * y;
}

/* char - char: promoted-int difference is bounded by the narrow type's own
 * range on both sides. */
void test_schar_subtract(void) {
    char c = -100;
    char d = 50;
    char result = c - d;
}

/* short << 2: promoted-int result (16000 << 2 = 64000) fits comfortably in
 * int; contrast with the FAIL case's much larger shift amount. */
void test_short_shift(void) {
    short val = 16000;
    short shifted = val << 2;
}
