/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: ABS evaluates x twice; a different macro defined later with a
 * statement expression does not make ABS safe.
 */

#define ABS(x) (((x) < 0) ? -(x) : (x))

void h(int n) {
    int m = ABS(++n);  // VIOLATION
    (void)m;
}

#define ONCE(x) ({ int _t = (x); _t; })
