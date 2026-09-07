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
 *
 * The operand magnitudes are the originals, deliberately. What changed
 * (task 925) is that each result is now stored somewhere that holds it:
 * `short result = a + b;` at these magnitudes is a safe *computation* and a
 * truncating *store*, and this file is about the computation. The store is
 * tests/fail/narrow_truncating_store.c. The last case here keeps a narrow
 * destination, to hold the line that a narrow store which fits is silent.
 */

/* short + short: promoted-int sum tops out in the low tens of thousands,
 * nowhere near INT_MAX. */
void test_short_add(void) {
    short a = 32000;
    short b = 1000;
    int result = a + b;
}

/* unsigned char * unsigned char: promoted-int product maxes at 255*255 =
 * 65025, far below INT_MAX. */
void test_uchar_multiply(void) {
    unsigned char x = 200;
    unsigned char y = 2;
    int result = x * y;
}

/* char - char: promoted-int difference is bounded by the narrow type's own
 * range on both sides. */
void test_schar_subtract(void) {
    char c = -100;
    char d = 50;
    int result = c - d;
}

/* short << 2: promoted-int result (16000 << 2 = 64000) fits comfortably in
 * int; contrast with the FAIL case's much larger shift amount. */
void test_short_shift(void) {
    short val = 16000;
    int shifted = val << 2;
}

/* A narrow destination that does hold the value: safe computation, safe
 * store, nothing to report. */
void test_short_add_fits(void) {
    short a = 3200;
    short b = 1000;
    short result = a + b;
}

/* A guard on the operand: whatever `data + 1` computes from the unguarded
 * dataflow, the value that reaches the store is what the test admits. Juliet's
 * CWE-190 good sink is this exact shape, and the branch here is in fact dead.
 * No definite claim is available, so nothing is reported. */
void test_guarded_operand(void) {
    char data;
    data = 127;
    if (data < 127) {
        char result = data + 1;
    }
}
