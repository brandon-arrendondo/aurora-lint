/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - sizeof is one term of a larger index
 *
 * The index is i + 7, not 7; i is the caller's.
 */

int element(int i)
{
    char buf[8] = {0};
    char a[4] = {0};
    return a[i + sizeof(buf) - 1] + buf[0];
}
