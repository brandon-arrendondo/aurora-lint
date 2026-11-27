/*
 * Rule: ARR00-C
 * Source: synthetic
 * Status: FAIL - A loop variable that is never given a value bounds an array access
 * Expect: count=2
 *
 * The first loop has no initializer, so its counter is read uninitialized.
 * The second loop's initializer sets only the counter; its bound is
 * declared without a value and never assigned.
 */

void counter_without_an_initializer(void)
{
    int h;
    int a[4];
    for (; h < 4; h++) { /* Expect: here */
        a[h] = 0;
    }
}

void bound_not_set_by_the_initializer(void)
{
    int h;
    int n;
    int a[4];
    for (h = 0; h < n; h++) { /* Expect: here */
        a[h] = 0;
    }
}
