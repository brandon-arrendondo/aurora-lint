/*
 * Rule: INT13-C
 * Source: raylib src/rtextures.c ResizeImage (task 754)
 * Status: FAIL - Should trigger INT13-C violation
 *
 * Guard rail: the shifted VALUE can be a compound arithmetic expression
 * (not itself a shift), and the fix must still resolve a signed variable
 * out of it -- only a nested SHIFT's count operand is off-limits.
 */

void shift_value_operand_arithmetic_compound(void) {
    int x = 3;
    int xRatio = 7;
    unsigned int result = (x * xRatio) >> 16;
}
