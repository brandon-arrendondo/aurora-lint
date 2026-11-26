/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The guard tests another variable of the index's name
 * Expect: count=5
 *
 * Each guard compares a `d` with the array's size, but not the `d` the
 * access reads. An enclosing `if (d < 10)` on an outer `d`, a local or a
 * parameter, does not bound an inner `int d` that shadows it. Nor does an
 * `if (d < 10)` on an inner block's own `d` bound the parameter `d` once
 * the block ends, whether the array is fixed or reached through a pointer
 * parameter.
 */
#include <stdlib.h>

int get(void);
void use(int);

void outer_local_guarded_inner_read(const char *t)
{
    int b[10];
    int d = get();
    if (d < 10) {
        int d = atoi(t) & 0x7fff;
        b[d] = 1; /* Expect: here */
    }
}

void outer_parameter_guarded_inner_read(const char *t, int d)
{
    int b[10];
    if (d < 10) {
        int d = atoi(t) & 0x7fff;
        b[d] = 1; /* Expect: here */
    }
}

void outer_parameter_guarded_both_ends_inner_read(const char *t, int d)
{
    int b[10];
    if (d >= 0 && d < 10) {
        int d = atoi(t);
        b[d] = 1; /* Expect: here */
    }
}

void inner_shadow_guarded_parameter_read(int d, const char *t)
{
    int b[10];
    {
        int d = atoi(t);
        if (d < 10)
            use(d);
    }
    b[d] = 1; /* Expect: here */
}

void inner_shadow_guarded_parameter_read_through_pointer(int *a, int d, const char *t)
{
    {
        int d = atoi(t);
        if (d < 10)
            use(d);
    }
    a[d] = 1; /* Expect: here */
}
