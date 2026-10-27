/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: next's body calls (bump) (1), the function bump in parentheses,
 * and bump writes a static, so TWICE(next()) changes it twice.
 */

#define TWICE(x) ((x) + (x))

static int counter;

static int bump(int by) {
    counter += by;
    return counter;
}

static int next(void) {
    return (bump) (1);
}

int use(void) {
    return TWICE(next());  // Expect: here
}
