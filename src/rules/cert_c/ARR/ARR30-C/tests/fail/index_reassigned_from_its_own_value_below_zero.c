/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The index is stored back from its own value, which may then be negative
 * Expect: count=3
 *
 * A test proves the index is not negative, or is positive, and then the
 * index is stored back from its own value in a way that may take it below
 * zero: one subtracted from a value that may be 0, a negation, and a
 * conditional whose other arm keeps a value no test bounded below.
 */
#include <stdlib.h>

void decremented_after_a_lower_guard(const char *s)
{
    int b[10];
    int d = atoi(s);
    if (d < 0)
        return;
    d = d - 1;
    if (d < 10)
        b[d] = 1; /* Expect: here */
}

void negated_after_a_positive_test(const char *s)
{
    int b[10];
    int d = atoi(s);
    if (d <= 0)
        return;
    d = -d;
    if (d < 10)
        b[d] = 1; /* Expect: here */
}

void reduced_in_one_arm_only(const char *s)
{
    int b[10];
    int d = atoi(s);
    d = (d > 3) ? d - 3 : d;
    if (d < 10)
        b[d] = 1; /* Expect: here */
}
