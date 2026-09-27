/*
 * Rule: PRE31-C
 * Source: CERT EXP44-C noncompliant example (_Generic)
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: S never evaluates val (a _Generic controlling expression is not
 * evaluated), so it is an unsafe macro and a++ never happens.
 */

#include <stdio.h>

#define S(val) _Generic(val, int : 2, \
                             short : 3, \
                             default : 1)
void func(void) {
  int a = 0;
  int b = S(a++);  // VIOLATION
  printf("%d, %d\n", a, b);
}
