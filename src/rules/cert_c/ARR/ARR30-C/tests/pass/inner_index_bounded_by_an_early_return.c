/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A guard already passed bounds the inner index of a two-dimensional access
 *
 * The early return leaves `col` below 4, the length of a row of `grid`,
 * as it would bound an index into a one-dimensional array.
 */

static int grid[3][4];

int cell(unsigned col)
{
    if (col >= 4)
        return 0;
    return grid[1][col];
}
