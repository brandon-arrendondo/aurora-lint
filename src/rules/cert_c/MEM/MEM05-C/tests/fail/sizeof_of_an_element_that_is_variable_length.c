/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: FAIL - sizeof of an element that is itself a VLA
 * Expect: count=2
 *
 * A row of `int grid[][n]` is an `int [n]`, and so is what `p[0]` reads
 * through `char (*p)[n]`: each `sizeof` is evaluated at run time (C11
 * 6.5.3.4p2), so each array sized by one is variable-length.
 */
void sink(char *p);

void runtime_sizes(int n, int grid[][n], char (*p)[n])
{
    char by_row[sizeof grid[0]];
    char by_pointee[sizeof (p[0])];
    sink(by_row);
    sink(by_pointee);
}
