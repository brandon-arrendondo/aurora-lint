/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A guard that admits the row length leaves the inner index one past it
 * Expect: count=1
 *
 * `col > 4` returns only above 4, so `col` may be 4, one past the end of a
 * row of `grid`.
 */

static int grid[3][4];

int cell(unsigned col)
{
    if (col > 4)
        return 0;
    return grid[1][col]; /* Expect: here */
}
