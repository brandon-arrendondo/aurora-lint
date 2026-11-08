/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A branch in an arm overwrites its own store
 *
 * The value past the end is used and replaced in the branch.
 */

int buf[4];
int c;

int element(void)
{
    int n = 0;
    int i = 1;
#if A
    if (c) {
        i = 9;
        n = i;
        i = 2;
    }
#endif
    return buf[i] + n;
}
