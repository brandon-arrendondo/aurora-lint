/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A stepped variable does not hold its last assigned constant
 *
 * `i = 3` is the only plain assignment, but `i++` moves `i` to 4, one past
 * the end of `buf`.
 */

int fill(void)
{
    int buf[4];
    int i = 3;
    i++;
    buf[i] = 1;
    return buf[0];
}
