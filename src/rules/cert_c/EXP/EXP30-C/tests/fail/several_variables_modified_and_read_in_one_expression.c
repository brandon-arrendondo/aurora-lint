/*
 * Rule: EXP30-C
 * Status: FAIL - Should trigger EXP30-C violation
 *
 * Each expression modifies and reads several variables without a sequence
 * point between, so each finding names all of them.
 */

int in_an_initializer(int i, int j, int k) {
  int r = i++ + j++ + k++ + i + j + k;
  return r;
}

int in_an_assignment(int i, int j, int k) {
  int r;
  r = i++ + j++ + k++ + i + j + k;
  return r;
}
