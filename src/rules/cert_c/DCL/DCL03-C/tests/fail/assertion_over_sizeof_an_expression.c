/*
 * Rule: DCL03-C
 * Source: synthetic
 * Status: FAIL - An assertion over sizeof of an expression of fixed type
 * Expect: count=3
 *
 * `sizeof` of an expression whose type is not a variable-length array is
 * an integer constant (C11 6.5.3.4p2): a dereferenced pointer to a struct,
 * an element of a fixed-size array and a member each have a fixed type,
 * so a static assertion could test each condition.
 */
#include <assert.h>

struct header { int len; char tag[4]; };

void check(struct header *p, int i)
{
    int table[8];
    assert(sizeof(*p) >= 8);
    assert(sizeof(table[i]) * 8 == sizeof(table));
    assert(sizeof(p->tag[0]) == 1);
}
