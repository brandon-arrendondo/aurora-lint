/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: only a WIN build defines USE_FN, so every other build defines
 * square, which evaluates its argument twice.
 */

#if defined(WIN)
#define USE_FN
#endif

#if !defined(USE_FN)
#define square(n) ((n) * (n))
#endif

static int counter;

static int next(void) {
    return ++counter;
}

int k(void) {
    return square(next());  // Expect: here
}
