/*
 * Rule: FLP30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FLP30-C violation
 *
 * A floating variable declared in a for initializer that the controlling
 * expression does not test is an accumulator, not a loop counter (CERT's
 * definition). The integer n is the counter.
 */

double sum_down(int n, const double *v) {
  double acc = 0.0;
  for (double scale = 1.0; n > 0; n--) {
    acc += v[n - 1] * scale;
  }
  return acc;
}
