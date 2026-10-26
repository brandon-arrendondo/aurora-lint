/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: the condition reads the argument only under sizeof, which does
 * not evaluate it, and each ?: arm evaluates it once; one arm runs, so
 * the argument is evaluated exactly once (the shape of the C library's
 * type-generic classification macros, such as isnan).
 */

float f4(float);
double f8(double);
long double fl(long double);

#define CLASSIFY(x) \
    (sizeof(x) == sizeof(float) ? f4(x) \
     : sizeof(x) == sizeof(double) ? f8(x) : fl(x))

static double state;

static double next(void) {
    return state += 1.0;
}

double k(void) {
    return CLASSIFY(next());
}
