/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: PASS - sizeof of an expression whose type is not variably modified
 *
 * `sizeof` of an expression is an integer constant unless the expression
 * has a variable-length array type (C11 6.5.3.4p2). A dereferenced pointer
 * to a struct, an element of a fixed-size array and an arithmetic sum have
 * fixed types, so each array has a constant size.
 */
struct header { int len; char tag[4]; };

void sink(char *p);

void fixed_sizes(struct header *p, int i)
{
    int table[8];
    char copy[sizeof(*p)];
    char element[sizeof(table[i]) * 2];
    char sum[sizeof(i + 1)];
    sink(copy);
    sink(element);
    sink(sum);
}
