/* Rule: INT08-C
 * Source: testcases
 * Status: FAIL - narrow-typed multiplication/shift whose promoted-int
 * result can genuinely exceed INT_MAX (task 755).
 *
 * `+`/`-` on narrow (char/short) operands can never overflow a >=32-bit
 * promoted `int` -- the widest narrow magnitude (unsigned short's 65535)
 * combined with another narrow value tops out in the low hundred
 * thousands. `*` and `<<` don't have that guarantee: two operands near
 * their type's max can still exceed INT_MAX once promoted, which is what
 * these cases exercise.
 */

/* Case 1: unsigned short multiplication whose promoted-int product can
 * exceed INT_MAX (65535 * 65535 = 4294836225, > 2^31-1). */
void test_ushort_multiply_overflow(void) {
    unsigned short x = 60000;
    unsigned short y = 60000;
    unsigned short result = x * y;
}

/* Case 2: unsigned short left-shifted far enough that the promoted-int
 * result can exceed INT_MAX (65535 << 20 far exceeds 2^31-1). */
void test_ushort_shift_overflow(void) {
    unsigned short val = 60000;
    int shifted = val << 20;
}
