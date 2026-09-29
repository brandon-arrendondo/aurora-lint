/*
 * Rule: FLP02-C
 * Source: regression
 * Status: FAIL - `sqrt(x) * 2.0 == r` compares two doubles
 *
 * sqrt is the <math.h> function, whose result is double by the standard;
 * its header is not expanded, so the call is typed by that, including when
 * it is an operand of a larger expression rather than the whole operand.
 */

#include <math.h>

int is_double_root(double x, double r)
{
    return sqrt(x) * 2.0 == r;
}
