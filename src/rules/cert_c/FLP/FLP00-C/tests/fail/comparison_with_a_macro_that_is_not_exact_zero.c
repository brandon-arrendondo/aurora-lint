/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger FLP00-C violation
 * Expect: count=7
 *
 * A macro is a zero only when every definition in force is one: not when
 * one #if arm defines it otherwise, not after an #undef replaces it, not
 * for a nonzero character constant or an expression, and not when it is
 * function-like. A variable named zero is a variable.
 */

#define TINY 1e-9
#define SEPARATOR ','
#define ZERO_SUM (0.0 + 0.0)
#define ZERO_CALL() 0.0

#ifdef EXACT
#define EPSILON 0.0
#else
#define EPSILON 1e-6
#endif

#define REPLACED 0.0
#undef REPLACED
#define REPLACED 1.0

int compare(double x) {
    double zero = 0.0;
    if (x == TINY) /* Expect: here */
        return 1;
    if (x == SEPARATOR) /* Expect: here */
        return 2;
    if (x == ZERO_SUM) /* Expect: here */
        return 3;
    if (x == ZERO_CALL()) /* Expect: here */
        return 4;
    if (x == EPSILON) /* Expect: here */
        return 5;
    if (x == REPLACED) /* Expect: here */
        return 6;
    return x == zero; /* Expect: here */
}
