/*
 * Rule: MSC14-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

unsigned int si;
unsigned int si2;
unsigned int sum;

if (si < 0 || si2 < 0) {
  /* Handle error condition */
}
if (INT_MAX - si < si2) {
  /* Handle error condition */
}
sum = si + si2;