/*
 * Rule: INT32-C
 * Source: synthetic
 * Status: FAIL - Should trigger INT32-C violation
 *
 * `!d` has type int (C11 6.5.3.3p5) even when d is a double, so this is a
 * signed integer addition that overflows when i is INT_MAX and d is 0.
 */
int add_negation(int i, double d) {
    return i + !d; // violation
}
