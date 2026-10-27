/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: the default value defines SQ_FAST, but a WIN build undefines it
 * again, so a WIN build compiles the #else arm of sq, which evaluates its
 * argument twice.
 */

#ifndef SQ_FAST
#define SQ_FAST 1
#endif

#if defined(WIN)
#undef SQ_FAST
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
