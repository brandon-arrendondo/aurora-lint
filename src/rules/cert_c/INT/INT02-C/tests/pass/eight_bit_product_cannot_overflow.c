/*
 * Rule: INT02-C
 * Source: regression
 * Status: PASS - Should NOT trigger INT02-C violation
 *
 * Two 8-bit operands reach at most 255 * 255 = 65025, which fits in int, so
 * the promotion is harmless. Signed 16-bit is safe for the same reason:
 * 32767 * 32767 also fits.
 */

unsigned int byte_product(unsigned char a, unsigned char b) {
  unsigned int wide = a * b;

  return wide;
}

int signed_short_product(short a, short b) {
  int wide = a * b;

  return wide;
}
