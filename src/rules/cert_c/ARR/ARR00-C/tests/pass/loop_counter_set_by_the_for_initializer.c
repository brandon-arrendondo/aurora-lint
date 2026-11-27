/*
 * Rule: ARR00-C
 * Source: synthetic
 * Status: PASS - A loop variable declared earlier is set by the for's own initializer
 *
 * Each loop variable is declared without a value before the loop, and the
 * loop's initializer stores one before the condition first reads it: a
 * plain assignment, one inside a comma expression, and a bound set in the
 * same initializer as the counter.
 */

void counter_compared_with_a_constant(void)
{
    int h;
    char buf[100];
    for (h = 0; h < 1; h++) {
        buf[0] = '\0';
    }
}

void counter_set_in_a_comma_expression(int *out)
{
    int h, k;
    for (k = 1, h = 0; h < 4; h++) {
        out[h] = k;
    }
}

void bound_set_beside_the_counter(void)
{
    int i, n;
    int a[8];
    for (i = 0, n = 8; i < n; i++) {
        a[i] = 0;
    }
}
