/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: the default value of SQ_FAST sits in the #else of an #if 0,
 * which every build compiles, so every build defines SQ_FAST and compiles
 * sq as sq_fn, which evaluates its argument once.
 */

#if 0
#define SQ_FAST_OLD 1
#else
#ifndef SQ_FAST
#define SQ_FAST 1
#endif
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
