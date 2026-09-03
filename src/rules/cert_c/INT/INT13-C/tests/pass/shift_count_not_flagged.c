/*
 * Rule: INT13-C
 * Source: run-229 audited-residue adjudication (task 754)
 * Status: PASS - Should NOT trigger INT13-C violation
 *
 * All three of these are the same FP class: a signed variable used only as
 * a shift COUNT (or nested inside one) was being reported as the "signed
 * operand" of the enclosing bitwise expression, even though the actual
 * VALUE operand is unsigned. A shift count's signedness is INT34-C's
 * concern, not INT13-C's -- at any nesting depth.
 */

void shift_count_not_flagged(void) {
    unsigned char tmp = 0;
    int i = 3;
    unsigned int result1 = tmp >> i;

    int iId = 5;
    unsigned int result2 = (unsigned int)1 << ((iId - 1) % 32);

    unsigned short exclMask = 0xFF;
    unsigned int result3 = exclMask & (1 << i);
}
