/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The index is stored back from its own value where a test proves it is not negative
 *
 * Each index starts as atoi's result, of either sign, and is stored back
 * into itself under a test that proves the value stored is not negative:
 * the false arm of `d < 0 ? 0 : d`, an arm under an earlier `if (d < 0)
 * return;`, and a subtraction of no more than the lower bound the test
 * proves.
 */
#include <stdlib.h>

void clamped_below_by_a_conditional(const char *s)
{
    int b[10];
    int d = atoi(s);
    d = (d < 0) ? 0 : d;
    if (d >= 10)
        return;
    b[d] = 1;
}

void capped_after_a_lower_guard(const char *s)
{
    int b[10];
    int d = atoi(s);
    if (d < 0)
        return;
    d = d > 3 ? 1 : d;
    if (d < 10)
        b[d] = 1;
}

void reduced_in_the_arm_that_proves_it_large(const char *s)
{
    int b[10];
    int d = atoi(s);
    if (d < 0)
        return;
    d = (d > 3) ? d - 3 : d;
    if (d < 10)
        b[d] = 1;
}

void reduced_by_no_more_than_its_lower_bound(const char *s)
{
    int b[10];
    int d = atoi(s);
    if (d < 2)
        return;
    d = d - 2;
    if (d < 10)
        b[d] = 1;
}
