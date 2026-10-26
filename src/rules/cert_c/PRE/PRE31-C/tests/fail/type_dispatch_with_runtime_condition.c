/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: the condition evaluates the argument at run time and the chosen
 * arm evaluates it again, so every path evaluates it twice.
 */

float f4(float);
double f8(double);

#define POSITIVE_OR(x) ((x) > 0 ? f8(x) : f4(x))

static double state;

static double next(void) {
    return state += 1.0;
}

double k(void) {
    return POSITIVE_OR(next());  // Expect: here
}
