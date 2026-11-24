/*
 * Rule: DCL03-C
 * Source: synthetic
 * Status: PASS - an assertion over sizeof a row that is a VLA
 *
 * A row of `int grid[][n]` is an `int [n]`, so its `sizeof` is evaluated
 * at run time (C11 6.5.3.4p2) and no static assertion can test it.
 */
#include <assert.h>

void check(int n, int grid[][n])
{
    assert(sizeof grid[0] == 16);
}
