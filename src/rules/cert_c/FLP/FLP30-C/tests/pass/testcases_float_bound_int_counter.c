/*
 * Rule: FLP30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FLP30-C violation
 *
 * A floating value compared against an integer counter is not a counter
 * when the loop never changes it by a fixed amount, and a floating
 * variable halved each iteration is not changed by a fixed amount.
 */

void float_bound(double limit) {
  for (int i = 0; i < limit; i++) {
  }
}

void halving(double eps) {
  double h = 1.0;
  while (h > eps) {
    h *= 0.5;
  }
}
