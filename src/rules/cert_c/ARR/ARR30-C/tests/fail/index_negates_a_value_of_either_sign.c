/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The index negates a value that may be positive
 * Expect: count=6
 *
 * Each index is the negation of a local that may hold either sign, as
 * `atoi`'s result may, so it is negative whenever that value is positive,
 * and only an upper bound is checked. Nothing proves the value is not
 * positive where it is negated: there is no test at all, the test bounds
 * it below 2 rather than 1, or it is read again after the test. A local
 * negated in place, `d = -d;`, is read before the store, so what it
 * negates is the value it held.
 */
#include <stdlib.h>

void negated_copy(const char *s)
{
    int b[10];
    int n = atoi(s);
    int d = -n;
    if (d < 10)
        b[d] = 1; /* Expect: here */
}

void negated_copy_of_a_copy(const char *s)
{
    int b[10];
    int n = atoi(s);
    int m = n;
    int d = -m;
    if (d < 10)
        b[d] = 1; /* Expect: here */
}

void negated_in_place(const char *s)
{
    int b[10];
    int d = atoi(s);
    d = -d;
    if (d < 10)
        b[d] = 1; /* Expect: here */
}

void negated_without_a_sign_test(const char *s)
{
    int b[10];
    int w = atoi(s);
    int e = w;
    if (e >= 0 && e < 10)
        b[e] = 0;
    int d = w >= -2147483647 ? -w : 0;
    if (d < 10)
        b[d] = 1; /* Expect: here */
}

void negated_under_a_test_that_allows_one(const char *s)
{
    int b[10];
    int x = atoi(s);
    if (x < 2) {
        int d = -x;
        if (d < 10)
            b[d] = 1; /* Expect: here */
    }
}

void negated_after_a_new_value(const char *s, const char *t)
{
    int b[10];
    int x = atoi(s);
    if (x < 0) {
        x = atoi(t);
        int d = -x;
        if (d < 10)
            b[d] = 1; /* Expect: here */
    }
}
