/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: PASS - sizeof of an element of a one-dimensional VLA
 *
 * A subscript takes one array off the type, so an element of `int vla[n]`
 * is an int and an element of `vs` a struct, neither variably modified:
 * each `sizeof` is a constant (C11 6.5.3.4p2), as is that of an element
 * plus one and of a pointer element.
 */
struct pair { int m; int k; };

void sink(char *p);

void fixed_sizes(int n, int vla[n], struct pair vs[n], char *rows[n])
{
    char by_element[sizeof vla[0]];
    char by_struct[sizeof (vs[0])];
    char by_sum[sizeof (vla[0] + 1)];
    char by_pointer[sizeof rows[0]];
    sink(by_element);
    sink(by_struct);
    sink(by_sum);
    sink(by_pointer);
}
