/*
 * Rule: INT02-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * Where CHAR_BIT is 16 and int is 16 bits (a conforming target, and some DSPs
 * are built that way), unsigned char promotes to unsigned int, and the signed
 * counter is converted to unsigned before the comparison. Declared LP64, both
 * operands promote to int instead.
 */

void compare(unsigned char small_limit, short small_counter) {
  if (small_counter < small_limit) { /* VIOLATION */
    return;
  }
}
