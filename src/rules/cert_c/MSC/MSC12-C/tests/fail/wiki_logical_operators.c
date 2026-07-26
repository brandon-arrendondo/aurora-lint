/*
 * Rule: MSC12-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC12-C violation
 */

if (a == b && a == b) { // if the first one is true, the second one is too
  do_x();
}
if (a == c || a == c ) { // if the first one is true, the second one is too
  do_w();
}