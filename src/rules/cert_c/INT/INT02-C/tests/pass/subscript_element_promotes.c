/*
 * Rule: INT02-C
 * Source: regression (task 1213)
 * Status: PASS - Should NOT trigger INT02-C violation
 *
 * The indexed element is an unsigned char, which promotes to int, so the
 * comparison is signed-vs-signed. Resolving the element type is what makes
 * this answerable either way rather than silently skipped.
 */

int scan(unsigned char *buf, int limit) {
  if (limit < buf[0]) {
    return 1;
  }
  return 0;
}
