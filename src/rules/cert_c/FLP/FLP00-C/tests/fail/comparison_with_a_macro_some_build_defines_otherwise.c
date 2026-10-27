/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger FLP00-C violation
 * Expect: count=4
 *
 * A macro is a zero in every build only when every build defines it as
 * one. A default under #ifndef gives way to a definition on the command
 * line (-DTOLERANCE=1e-6), and a definition under #ifdef with no #else
 * leaves the name to whatever else defines it. A parameter that shares its
 * spelling with a macro defined further down is a parameter, and a cast to
 * a typedef does not say the type is arithmetic.
 */

#ifndef TOLERANCE
#define TOLERANCE 0.0
#endif

#ifdef HAVE_ZERO
#define HALF_ZERO 0.0
#endif

typedef double real;

int compare(double x, double LIMIT) {
    if (x == TOLERANCE) /* Expect: here */
        return 1;
    if (x == HALF_ZERO) /* Expect: here */
        return 2;
    if (x == LIMIT) /* Expect: here */
        return 3;
    return x == (real)0; /* Expect: here */
}

#define LIMIT 0.0
