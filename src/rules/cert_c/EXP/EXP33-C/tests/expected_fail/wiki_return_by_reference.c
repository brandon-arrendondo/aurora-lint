/*
 * Rule: EXP33-C
 * Source: wiki
 * Status: EXPECTED FAIL - Known limitation: set_flag() writes *sign_flag on two of
 * its three paths, so sign can still be read uninitialised. Once a prescan
 * supplies the callee's summary, EXP33-C treats the write to the output
 * parameter as unconditional and clears the uninitialised state -- the
 * MAY/MUST distinction that frees_params and unconditional_frees_params
 * draw for frees has no counterpart for output-parameter writes. Detected
 * without -d and missed with it; -d is the configuration every benchmark
 * uses. A genuine EXP33-C violation.
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