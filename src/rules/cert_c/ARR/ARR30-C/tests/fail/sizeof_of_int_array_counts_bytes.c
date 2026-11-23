/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - sizeof gives bytes, not elements
 * Settings: data_model=lp64
 * Expect: count=1
 *
 * sizeof(buf) is 32 on lp64, so the index is 31 into an array of 8.
 */

int last(void)
{
    int buf[8] = {0};
    return buf[sizeof(buf) - 1]; /* Expect: here */
}
