/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: the argument is `rc =`, a store that only the test build's arm
 * compiles; the release arm drops it. The call after the `)` is not part
 * of the argument, although a C parser reads `rc = work()` across it.
 */

#ifdef TEST
#define TESTONLY(X) X
#else
#define TESTONLY(X)
#endif

int work(void);

void h(void) {
    int rc;
    TESTONLY( rc = ) work();  // VIOLATION
    (void)rc;
}
