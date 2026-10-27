/*
 * Rule: DCL37-C
 * Status: PASS - an extern declaration in a block declares an identifier with
 * block scope, and an underscore followed by a lowercase letter is reserved
 * only at file scope.
 */

int use_externs(void) {
  extern int _counter;
  extern int _next(void);
  return _counter + _next();
}
