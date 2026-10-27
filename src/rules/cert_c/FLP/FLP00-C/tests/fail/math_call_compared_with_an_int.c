/*
 * Rule: FLP00-C
 * Source: aurora-lint
 * Status: FAIL - a <math.h> call returning double compared with an int
 * Expect: count=1
 *
 * sqrt returns double, so the int is converted and the comparison is a
 * floating-point one.
 */

#include <math.h>

int is_square_root(double x, int n) {
    return sqrt(x) == n; /* Expect: here */
}
