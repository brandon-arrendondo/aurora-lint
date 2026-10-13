/*
 * Rule: ARR30-C
 * Status: FAIL - the index is 5 for a 4-element array
 * Reason: `i = 6;` then `i -= 1;` leaves 5. Reading `i -= 1` as a store of
 * 1 calls the access safe.
 */

void subtract_short_of_the_bound(void)
{
    int a[4];
    int i;
    i = 6;
    i -= 1;
    a[i] = 0;
}
