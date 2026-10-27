/*
 * Rule: DCL37-C
 * Status: FAIL - an underscore followed by an uppercase letter is reserved
 * for any use, block scope included. It is reported once.
 * Expect: count=1
 */

int twice(int v) {
  int _Twice = v * 2; /* Expect: here */
  return _Twice;
}
