/*
 * Rule: DCL37-C
 * Status: FAIL - a function pointer's name sits inside parentheses in its
 * declarator, and is reserved all the same.
 * Expect: count=2
 */

int (*_handler)(int); /* Expect: here */

int call(int x) {
  int (*__local)(int) = _handler; /* Expect: here */
  return __local(x);
}
