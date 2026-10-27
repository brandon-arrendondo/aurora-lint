/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: a WIN build defines SQ_FAST itself, and the default value after
 * it defines SQ_FAST in every other build, so every build defines it.
 * Every build compiles sq as sq_fn, which evaluates its argument once; the
 * #else arm, which would evaluate it twice, is no build's.
 */

#if defined(WIN)
#define SQ_FAST 1
#endif

#ifndef SQ_FAST
#define SQ_FAST 1
#endif

int sq_fn(int);

#ifdef SQ_FAST
#define sq(x) sq_fn(x)
#else
#define sq(x) ((x) * (x))
#endif

int f(int i) {
    return sq(i++);
}
