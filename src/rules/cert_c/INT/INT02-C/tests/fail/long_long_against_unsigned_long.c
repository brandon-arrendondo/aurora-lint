/*
 * Rule: INT02-C
 * Source: regression
 * Status: FAIL - on a declared LP64 target
 * Settings: data_model=lp64
 *
 * long long outranks unsigned long, but on LP64 both are 64 bits: the signed
 * operand is converted to unsigned long long, so a negative total compares
 * as a large value.
 */

int over(long long total, unsigned long limit) {
  return total > limit; /* VIOLATION */
}
