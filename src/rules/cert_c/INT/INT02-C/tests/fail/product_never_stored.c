/*
 * Rule: INT02-C
 * Source: regression
 * Status: FAIL - Should trigger INT02-C violation
 *
 * Same undefined multiplication with no destination at all. Whether the
 * product is stored is irrelevant to whether it overflows.
 */

int compare_product(unsigned short x, unsigned short y, long limit) {
  if (x * y > limit) {
    return 1;
  }
  return 0;
}
