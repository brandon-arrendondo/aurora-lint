/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: the argument is `total +`, which changes nothing; the call with
 * a side effect comes after the `)`, outside the invocation, although a C
 * parser reads `total + bump()` across it.
 */

#ifdef TEST
#define TESTONLY(X) X
#else
#define TESTONLY(X)
#endif

static int counter;

static int bump(void) {
    return ++counter;
}

int h(int total) {
    return TESTONLY( total + ) bump();
}
