/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - An allocation sizes only the row it is stored to
 *
 * `m[0][1] = malloc(3 * sizeof(int))` sizes the rows `m[i][j]` at three. It
 * says nothing of how many rows `m[0]` holds, so `m[0][5]` is not judged
 * against three, and `m[0][1][2]` is within the row.
 */
#include <stdlib.h>

int within_an_allocated_row(int ***m)
{
    m[0][1] = malloc(3 * sizeof(int));
    return m[0][1][2] + m[0][5][2];
}
