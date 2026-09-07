/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation.
 *
 * sqlite's fts5CsrPoslist shape, reduced. outer() covers *pv on every
 * returning path, but one arm covers it only by handing pv to inner(), which
 * a structural walk of outer's own body cannot see through. Without that
 * forwarded leg pv is demoted to a MAY-write and every caller reports `v`
 * uninitialised -- once per caller, not once per callee (task 1011,
 * tools_sqc).
 *
 * The output parameter is `int *` and not sqlite's `const u8 **` on purpose:
 * EXP33-C does not report an uninitialised POINTER local at all, so a fixture
 * written with the original types passes whether the forwarded leg is
 * credited or not, i.e. for no reason. Verified load-bearing: `v` is reported
 * when the transitive discharge is disabled.
 */

int use_values(int v, int n) { return v + n; }

static int inner(int *out) {
  *out = 1;
  return 0;
}

static int outer(int flag, int *pv, int *pn) {
  if (flag) {
    *pv = 0;
    *pn = 0;
  } else {
    *pn = inner(pv);
  }
  return 0;
}

int caller(int flag) {
  int v;
  int n;
  if (outer(flag, &v, &n) == 0) {
    return use_values(v, n);
  }
  return -1;
}
