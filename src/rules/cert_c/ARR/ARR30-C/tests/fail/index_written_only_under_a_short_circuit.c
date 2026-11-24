/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A write that may not run leaves an earlier out-of-range value
 * Expect: count=3
 *
 * Each masked or in-range store sits under `&&`, so when its left operand
 * is false the index keeps its earlier value, 99 in `buf[64]` or 9 in
 * `buf[5]`: the store in range proves nothing about the read.
 */

extern int get(void);

int under_and(int c)
{
    int buf[64] = {0};
    int n = 99;
    (void)(c && (n = get() & 63));
    return buf[n]; /* Expect: here */
}

int in_a_condition(int c)
{
    int buf[64] = {0};
    int n = 99;
    if (c && (n = get() & 63))
        return 0;
    return buf[n]; /* Expect: here */
}

int a_constant_under_and(void)
{
    int buf[5] = {0};
    int i = 9;
    (void)(get() && (i = 1));
    return buf[i]; /* Expect: here */
}
