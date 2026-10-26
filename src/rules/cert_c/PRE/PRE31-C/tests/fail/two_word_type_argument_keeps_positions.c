/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: the preprocessor splits arguments at top-level commas, so
 * `unsigned long` is one argument and `n++` is the second, which the
 * body evaluates twice. Read as C, `unsigned long` is two arguments and
 * `n++` would land on the third parameter, which is evaluated once.
 */

#define SCALE(t, x, y) ((t)(x) * (t)(x) + (t)(y))

unsigned long s(unsigned n) {
    return SCALE(unsigned long, n++, 1);  // VIOLATION
}
