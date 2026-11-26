/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The negated value is proved not positive, or has one sign
 *
 * Each index negates a local, and either a test that governs the
 * negation proves the local is not positive there (the absolute-value
 * idiom, a width made positive under `if (w < 0)`, `x <= 0`, the false
 * arm of `x > 0`), or the local holds only a constant.
 */
#include <stdlib.h>

void absolute_value(const char *s)
{
    int b[10];
    int d = atoi(s);
    if (d < 0) {
        d = -d;
        if (d < 10)
            b[d] = 1;
    }
}

void width_made_positive(const char *s)
{
    int b[10];
    int w = atoi(s);
    int e = w;
    if (e >= 0 && e < 10)
        b[e] = 0;
    if (w < 0) {
        int d = w >= -2147483647 ? -w : 0;
        if (d < 10)
            b[d] = 1;
    }
}

void not_positive_by_test(const char *s)
{
    int b[10];
    int x = atoi(s);
    if (x <= 0) {
        int d = -x;
        if (d < 10)
            b[d] = 1;
    }
}

void false_arm_of_positive_test(const char *s)
{
    int b[10];
    int x = atoi(s);
    int d = x > 0 ? x : -x;
    if (d < 10)
        b[d] = 1;
}

void negated_constant(void)
{
    int b[10];
    int n = -3;
    int d = -n;
    if (d < 10)
        b[d] = 1;
}
