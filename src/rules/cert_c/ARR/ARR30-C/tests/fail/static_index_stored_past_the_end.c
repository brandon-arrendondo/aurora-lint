/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A static index holds a store past the end on some call
 * Expect: count=2
 *
 * In `both_ways` every path stores 7 or 8 before the read of `buf[5]`.
 * In `next_call` the store of 9 comes after the access, but `i` is static:
 * the second call reads `buf[9]`.
 */

int both_ways(int c)
{
    int buf[5] = {0};
    static int i = 0;
    if (c) {
        i = 7;
    } else {
        i = 8;
    }
    return buf[i]; /* Expect: here */
}

int next_call(void)
{
    int buf[5] = {0};
    static int i = 1;
    int r = buf[i]; /* Expect: here */
    i = 9;
    return r;
}
