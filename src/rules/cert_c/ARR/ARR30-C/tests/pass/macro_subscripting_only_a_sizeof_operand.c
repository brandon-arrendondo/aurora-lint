/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A macro whose only subscript is a sizeof operand reads no element
 *
 * `sizeof (a)[i]` is `sizeof((a)[i])`: the subscript is part of the
 * operand, which is never evaluated, so `ELEM_SIZE(tbl, 2)` reads nothing
 * from `tbl`.
 */

#define ELEM_SIZE(a, i) sizeof (a)[i]

static int tbl[4];

unsigned elem_size(void)
{
    return ELEM_SIZE(tbl, 2);
}
