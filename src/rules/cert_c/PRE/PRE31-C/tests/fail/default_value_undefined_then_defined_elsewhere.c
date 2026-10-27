/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: a WIN build undefines SQ_FAST, and only a build that also has
 * WIN_FAST defines it again, so a WIN build without WIN_FAST compiles the
 * #else arm of sq, which evaluates its argument twice.
 */

#ifndef SQ_FAST
#define SQ_FAST 1
#endif

#ifdef WIN
#undef SQ_FAST
#ifdef WIN_FAST
#define SQ_FAST 2
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
