/*
 * Rule: INT02-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * ISO C guarantees int only 16 bits. Both unsigned char operands promote to
 * int wherever int holds their values, and 255 * 255 = 65025 exceeds a 16-bit
 * INT_MAX: the multiplication can overflow on a conforming target. Declared
 * LP64, the same code is safe (see the pass fixture of the same shape).
 */

unsigned int byte_product(unsigned char a, unsigned char b) {
  unsigned int wide = a * b; /* VIOLATION */

  return wide;
}
