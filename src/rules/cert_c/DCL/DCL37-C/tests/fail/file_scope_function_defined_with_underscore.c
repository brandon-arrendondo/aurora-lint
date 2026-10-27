/*
 * Rule: DCL37-C
 * Status: FAIL - a function is defined at file scope, where every name that
 * begins with an underscore is reserved.
 * Expect: count=1
 */

static int _helper(int x) { /* Expect: here */
  return x + 1;
}

int use_helper(int x) { return _helper(x); }
