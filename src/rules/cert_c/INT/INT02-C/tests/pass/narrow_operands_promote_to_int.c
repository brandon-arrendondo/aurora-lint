/*
 * Rule: INT02-C
 * Source: regression (task 1186)
 * Status: PASS - Should NOT trigger INT02-C violation
 *
 * Both operands are narrower than int, so both promote to int and the
 * comparison is signed-vs-signed. No conversion defect.
 */

void compare(unsigned short small_limit, short small_counter) {
  if (small_counter < small_limit) {
    return;
  }
}
