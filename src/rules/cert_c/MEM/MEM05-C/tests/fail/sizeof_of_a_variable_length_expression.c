/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: FAIL - sizeof of an expression of variable-length array type
 * Expect: count=2
 *
 * `p` points to a variable-length array, so `*p` has one's type and
 * `sizeof(*p)` is evaluated at run time (C11 6.5.3.4p2): the array sized
 * by it is variable-length too.
 */
void sink(char *p);

void runtime_sizes(int n, char (*p)[n])
{
    char copy[sizeof(*p)];
    char twice[sizeof(*p) * 2];
    sink(copy);
    sink(twice);
}
