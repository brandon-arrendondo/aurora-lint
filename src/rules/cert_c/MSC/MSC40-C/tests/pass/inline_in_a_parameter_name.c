/*
 * Rule: MSC40-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger MSC40-C violation
 *
 * `inline` appears only inside a parameter name; the definition carries no
 * inline function specifier.
 */

unsigned total(unsigned inline_count) {
  static unsigned sum = 0;
  sum += inline_count;
  return sum;
}
