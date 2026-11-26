/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The guard tests the very variable the access reads
 *
 * A nested block declares its own `d`, but the guard and the access both
 * read the outer one: a parameter checked at both ends before the access,
 * a local an enclosing `if` bounds, and a pointer parameter's index
 * checked by the `if` around the access, and a parameter an assertion
 * bounds through a cast.
 */
#include <assert.h>
#include <stdlib.h>

void use(int);

void parameter_guarded_beside_a_shadow(int d)
{
    int b[10];
    if (d < 0 || d >= 10)
        return;
    {
        int d = 3;
        use(d);
    }
    b[d] = 1;
}

void local_guarded_beside_a_shadow(const char *t)
{
    int b[10];
    int d = atoi(t) & 0x7fff;
    {
        int d = 12;
        use(d);
    }
    if (d < 10) {
        b[d] = 1;
    }
}

void pointer_parameter_guarded(int *a, int d)
{
    {
        int d = 40;
        use(d);
    }
    if (d < 10)
        a[d] = 1;
}

void parameter_asserted_through_a_cast(int d)
{
    int b[10];
    {
        int d = 40;
        use(d);
    }
    assert((unsigned)d < 10);
    b[d] = 1;
}

void parameter_tested_through_a_cast(int *a, int d)
{
    if ((unsigned)d < 10)
        a[d] = 1;
}
