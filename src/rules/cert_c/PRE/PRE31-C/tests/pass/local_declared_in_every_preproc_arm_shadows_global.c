/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: every alternative of the #if group declares a local n, so in
 * every configuration reset's assignment writes that local, never the
 * global n. reset changes nothing a caller can see.
 */

#define TWICE(x) ((x) + (x))

int n;

static int reset(void) {
#if defined(_WIN32)
    long n;
#elif defined(__APPLE__)
    long long n;
#else
    int n;
#endif
    n = 0;
    return (int)n;
}

int use(void) {
    return TWICE(reset());
}
