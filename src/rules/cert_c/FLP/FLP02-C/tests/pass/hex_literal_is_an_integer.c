/*
 * Rule: FLP02-C
 * Source: regression
 * Status: PASS - `d == 0x1f` compares a double with an integer constant
 *
 * `0x1f` is the integer 31: in a hexadecimal constant `f` is a digit, not a
 * float suffix, and `e` is a digit, not an exponent. Only one operand is
 * floating-point, which this rule deliberately does not report.
 */

int is_31(double d)
{
    return d == 0x1f || d == 0x1e5;
}
