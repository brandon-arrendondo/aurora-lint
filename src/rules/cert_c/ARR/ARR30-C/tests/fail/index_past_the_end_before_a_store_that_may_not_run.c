/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The initial index reaches the access when the test is false
 * Expect: count=1
 *
 * The store of 2 runs only when c holds, so the 9 the index starts with
 * is the index on the other way. The last assignment in the function is
 * not the value at the access.
 */

int buf[4];

int element(int c)
{
    int i = 9;
    if (c)
        i = 2;
    return buf[i]; /* Expect: here */
}
