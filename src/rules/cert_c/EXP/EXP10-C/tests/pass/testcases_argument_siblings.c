/*
 * Rule: EXP10-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP10-C violation
 * Description: Two side-effecting calls that are both arguments of the same
 * call are deliberately not reported: the order is unspecified, but the
 * shape is every printf("%d %d", a(), b()) in ordinary C and the rule
 * targets operator operands and the designator-vs-argument case. If this
 * scope is widened, the new population needs adjudication first.
 */

#include <stdio.h>

extern int next_a(void);
extern int next_b(void);

void f(void) {
  printf("%d %d\n", next_a(), next_b());
}
