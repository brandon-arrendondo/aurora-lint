/*
 * Rule: MSC14-C
 * Source: wiki
 * Status: EXPECTED FAIL - Known limitation: this example's violation is
 * `~si` (bitwise complement) applied to a signed operand for an
 * overflow-detection idiom -- platform-dependent because bitwise
 * complement of a signed value is implementation-defined. That exact
 * pattern (unary ~ on a signed operand) is already detected by INT13-C
 * ("Use bitwise operators only on unsigned operands"); MSC14-C
 * deliberately does not duplicate that check and instead targets the
 * strerror_r() platform-dependent-return-type pattern from the wiki's
 * other example.
 */

signed int si;
signed int si2;
signed int sum;

if (si < 0 || si2 < 0) {
  /* Handle error condition */
}
if (~si < si2) {
  /* Handle error condition */
}
sum = si + si2;