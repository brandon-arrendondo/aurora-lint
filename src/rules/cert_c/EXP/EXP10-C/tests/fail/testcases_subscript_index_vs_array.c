/*
 * Rule: EXP10-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP10-C violation
 * Description: The array operand and the index of a subscript are
 * unsequenced: table()[next()] reads whichever table is current when the
 * index side effect happens to run.
 */

extern int *table(void);
extern int next(void);

int f(void) {
  return table()[next()];
}
