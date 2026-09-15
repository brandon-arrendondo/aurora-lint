/*
 * Rule: INT02-C
 * Source: regression (task 1213)
 * Status: FAIL - Should trigger INT02-C violation
 *
 * The overflow happens in the product, not the assignment: both operands
 * promote to int and 45000 * 50000 exceeds INT_MAX before anything is
 * stored. An earlier version required an int-ranked-or-wider destination
 * and so missed this.
 */

unsigned short truncating_store(void) {
  unsigned short x = 45000, y = 50000;
  unsigned short z = x * y;

  return z;
}
