/*
 * Rule: DCL05-C
 * Source: wiki (Windows example shape, typedef visible in the same file)
 * Status: FAIL - Should trigger DCL05-C violation
 *
 * Both halves of the defect: the typedef hides a pointer, and `const` on
 * the alias lands on the pointer rather than the POINT it points to.
 */

typedef struct tagPOINT {
    long x, y;
} POINT, *LPPOINT;

void func(const LPPOINT pt)
{
    pt->x = 0; /* compiles: pt is POINT *const, not const POINT * */
}
