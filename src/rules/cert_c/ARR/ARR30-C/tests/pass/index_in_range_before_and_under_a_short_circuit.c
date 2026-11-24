/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Every value the index may hold is in range
 *
 * In `under_and` the store under `&&` may not run, and the value before it,
 * 0, is in range too. In `in_a_condition` the condition's store always runs
 * and masks the index below the size.
 */

extern int get(void);

int under_and(int c)
{
    int buf[64] = {0};
    int n = 0;
    (void)(c && (n = get() & 63));
    return buf[n];
}

int in_a_condition(void)
{
    int buf[64] = {0};
    int n = get();
    if ((n = get() & 63))
        return 0;
    return buf[n];
}
