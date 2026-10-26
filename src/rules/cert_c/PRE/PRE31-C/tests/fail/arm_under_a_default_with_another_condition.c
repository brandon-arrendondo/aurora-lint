/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: SQ_NDEBUG is defined only where SQ_DEBUG is not, so a build
 * with SQ_DEBUG and without SQ_NDEBUG compiles the #else arm of sq, which
 * evaluates its argument twice. A condition with another term besides
 * !defined(SQ_NDEBUG) gives no default value.
 */

#if !defined(SQ_NDEBUG) && !defined(SQ_DEBUG)
#define SQ_NDEBUG 1
#endif

int sq_fn(int);

#ifdef SQ_NDEBUG
#define sq(x) sq_fn(x)
#else
#define sq(x) ((x) * (x))
#endif

int f(int i) {
    return sq(i++);  // Expect: here
}
