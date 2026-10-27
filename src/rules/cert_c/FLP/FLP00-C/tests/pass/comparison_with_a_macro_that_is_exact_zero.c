/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: PASS under the default preset; VIOLATION under strict and pedantic
 * Expect: default=clean strict=violation pedantic=violation count=5
 *
 * An object-like macro whose every definition in force is an exact zero is
 * a comparison with zero, as the literal is: under parentheses, a cast or a
 * sign, through another macro, and in every arm of an #if that defines it.
 */

#define ZERO 0.0
#define ZERO_F ((float)0)
#define NEGATIVE_ZERO (-0.0)
#define SAME_ZERO ZERO

#ifdef USE_FLOAT
#define REAL_ZERO 0.0f
#else
#define REAL_ZERO 0
#endif

int is_unset(double x, float y) {
    if (x == ZERO) /* Expect: here */
        return 1;
    if (y != ZERO_F) /* Expect: here */
        return 2;
    if (x == NEGATIVE_ZERO) /* Expect: here */
        return 3;
    if (x == SAME_ZERO) /* Expect: here */
        return 4;
    return x == REAL_ZERO; /* Expect: here */
}
