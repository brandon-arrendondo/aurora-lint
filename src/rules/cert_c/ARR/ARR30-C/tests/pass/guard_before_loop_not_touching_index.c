/*
 * Rule: ARR30-C
 * Source: real-world
 * Status: PASS - Should NOT trigger ARR30-C violation
 * Reason: the early-return guard precedes a loop that contains the access
 *         but never writes the index, so the bound it proved still holds on
 *         every iteration. Twin of the FAIL fixture where the loop body does
 *         write the index after the access.
 */

int rd(void);

int fill(void)
{
    char a[128];
    int res = rd();
    int k = rd();

    if (res < 0 || res >= (int) sizeof(a))
        return -1;
    while (k-- > 0) {
        a[res] = 0;
    }
    return 0;
}
