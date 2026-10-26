/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: only a WIN build defines USE_FN, so every other build defines
 * conv, which evaluates its argument once; in a WIN build conv is the
 * function, which does too.
 */

#if defined(WIN)
#define USE_FN
#endif

int use_once(int);

#if !defined(USE_FN)
#define conv(n) use_once((n))
#endif

static int counter;

static int next(void) {
    return ++counter;
}

int k(void) {
    return conv(next());
}
