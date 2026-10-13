/*
 * Rule: ARR30-C
 * Status: FAIL - The first access uses index 4 of a 4-element array
 * Reason: the access comes before the decrement, so the first trip writes
 * a[4].
 */

void count_down_late(void)
{
    int a[4];
    int i = 4;
    while (i > 0) {
        a[i] = 0;
        i--;
    }
}
