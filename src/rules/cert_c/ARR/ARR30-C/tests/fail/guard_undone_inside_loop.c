/*
 * Rule: ARR30-C
 * Source: real-world
 * Status: FAIL - the guard precedes the loop, but the loop body advances
 *         `res` after the access, so the second iteration indexes past what
 *         the guard proved.
 *
 * A write anywhere in a loop that encloses the access but not the guard
 * runs before the loop's next visit to the access; the reassignment check
 * therefore covers the whole loop body, not just the text before the access.
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
        res += 10;
    }
    return 0;
}
