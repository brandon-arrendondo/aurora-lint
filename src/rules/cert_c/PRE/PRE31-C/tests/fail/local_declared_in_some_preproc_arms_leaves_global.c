/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: the #if group has no #else, so a configuration that defines
 * neither macro declares no local n, and reset's assignment writes the
 * global n there: a proven side effect.
 */

#define TWICE(x) ((x) + (x))

int n;

static int reset(void) {
#if defined(_WIN32)
    long n;
#elif defined(__APPLE__)
    long long n;
#endif
    n = 0;
    return (int)n;
}

int use(void) {
    return TWICE(reset());  // VIOLATION
}
