/*
 * Rule: EXP33-C
 * Source: wiki
 * Status: FAIL - Should trigger EXP33-C violation
 *
 * The CERT wiki's own noncompliant example. set_flag() writes *sign_flag on
 * two of its three paths -- number == 0 writes nothing -- so is_negative()
 * can still read `sign` uninitialised. The callee's summary must therefore
 * report the output-parameter write as a MAY-write and leave the
 * uninitialised state standing; only unconditional_modifies_params, the
 * MUST set, clears it (task 988, tools_sqc).
 */

void set_flag(int number, int *sign_flag) {
  if (NULL == sign_flag) {
    return;
  }

  if (number > 0) {
    *sign_flag = 1;
  } else if (number < 0) {
    *sign_flag = -1;
  }
}

int is_negative(int number) {
  int sign;
  set_flag(number, &sign);
  return sign < 0;
}