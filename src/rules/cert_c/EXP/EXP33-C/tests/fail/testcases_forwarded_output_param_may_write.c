/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * The other direction of task 1011: classify() covers *out on one arm
 * directly and on the other only by forwarding to set_flag(), which writes
 * nothing when number == 0. A forwarded parameter is credited against the
 * callee's MUST set, so this obligation stays undischarged and `sign` is
 * still read uninitialised. Crediting a forward optimistically -- on the
 * mere fact that the parameter was passed -- would suppress this.
 */

static void set_flag(int number, int *sign_flag) {
  if (number > 0) {
    *sign_flag = 1;
  } else if (number < 0) {
    *sign_flag = -1;
  }
}

static void classify(int number, int *out) {
  if (number == 0) {
    set_flag(number, out);
  } else {
    *out = 2;
  }
}

int use_classify(int number) {
  int sign;
  classify(number, &sign);
  return sign;
}
