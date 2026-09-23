/*
 * Rule: INT02-C
 * Source: regression
 * Status: PASS - Should NOT trigger INT02-C violation
 *
 * The signed operand outranks the unsigned one, so it is the UNSIGNED value
 * that converts, which is value-preserving.
 */

void compare(long wide_signed, unsigned int narrow_unsigned) {
  if (wide_signed < narrow_unsigned) {
    return;
  }
}
