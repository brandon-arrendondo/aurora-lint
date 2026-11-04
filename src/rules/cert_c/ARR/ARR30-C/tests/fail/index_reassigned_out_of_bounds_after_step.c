/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - An index stepped and then reassigned holds the new constant
 *
 * The step comes before `i = 9`, so the access indexes 9.
 */

int fill(void)
{
    int buf[4];
    int i = 0;
    i++;
    i = 9;
    buf[i] = 1;
    return buf[0];
}
