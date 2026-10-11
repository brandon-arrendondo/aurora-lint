/*
 * Rule: FLP30-C
 * Source: testcases
 * Status: FAIL - Should trigger FLP30-C violation
 *
 * CERT defines a loop counter as an operand of the controlling comparison of
 * a do, while or for loop that the loop changes by a fixed amount. A while
 * or do loop counts as much as a for loop.
 */

void while_counter(void) {
  float x = 0.1f;
  while (x <= 1.0f) {
    x += 0.1f;
  }
}

void do_counter(void) {
  double d = 0.0;
  do {
    d = d + 0.25;
  } while (d < 2.0);
}
