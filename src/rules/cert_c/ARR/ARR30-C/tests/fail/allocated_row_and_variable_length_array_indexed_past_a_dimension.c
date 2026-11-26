/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - An allocated row, or an inner dimension of a variable length array, is passed
 * Expect: count=2
 *
 * `m[0][1] = malloc(3 * sizeof(int))` sizes the row `m[0][1]` at three, so
 * `m[0][1][3]` is one past it. In `int v[n][3][4]` the first dimension is
 * not constant, but the last is four, and `v[1][0][4]` is one past it.
 */
#include <stdlib.h>

int past_an_allocated_row(int ***m)
{
    m[0][1] = malloc(3 * sizeof(int));
    return m[0][1][3];
}

int past_the_last_dimension_of_a_variable_length_array(int n)
{
    int v[n][3][4];
    v[1][0][3] = 0;
    return v[1][0][4];
}
