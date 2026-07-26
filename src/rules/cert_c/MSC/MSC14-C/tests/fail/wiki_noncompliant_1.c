/*
 * Rule: MSC14-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC14-C violation
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