/*
 * Rule: EXP10-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP10-C violation
 * Description: Nesting sequences a call only against the call it is an
 * argument of. outer(inner(x)) + other() still has two unsequenced pairs
 * (inner vs other, outer vs other).
 */

extern int inner(int x);
extern int outer(int v);
extern int other(void);

int f(int x) {
  return outer(inner(x)) + other();
}
