/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: the file gives SQ_FAST a default value, so every build defines
 * it: either the build did before, or the default does. Every build
 * compiles sq as sq_fn, which evaluates its argument once; the #else arm,
 * which would evaluate it twice, is no build's.
 */

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
