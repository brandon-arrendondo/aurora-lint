/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: a WIN build undefines SQ_FAST only to define it again with
 * another value, so every build still defines it and compiles sq as sq_fn,
 * which evaluates its argument once.
 */

#ifndef SQ_FAST
#define SQ_FAST 1
#endif

#ifdef WIN
#undef SQ_FAST
#define SQ_FAST 2
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
