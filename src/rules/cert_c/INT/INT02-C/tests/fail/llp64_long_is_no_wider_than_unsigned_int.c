/*
 * Rule: INT02-C
 * Source: regression
 * Status: FAIL - on a declared LLP64 target
 * Settings: data_model=llp64
 *
 * long outranks unsigned int, but on LLP64 both are 32 bits, so long cannot
 * hold every unsigned int value: the usual arithmetic conversions make both
 * unsigned long, and a negative wide_signed compares as a large value.
 */

void compare(long wide_signed, unsigned int narrow_unsigned) {
  if (wide_signed < narrow_unsigned) { /* VIOLATION */
    return;
  }
}
