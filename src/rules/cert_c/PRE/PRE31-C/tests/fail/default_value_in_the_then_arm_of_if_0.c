/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: the default value of SQ_FAST sits in the first arm of an #if 0,
 * which no build compiles, so a build without SQ_FAST compiles the #else
 * arm of sq, which evaluates its argument twice.
 */

#if 0
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
    return sq(i++);  // Expect: here
}
