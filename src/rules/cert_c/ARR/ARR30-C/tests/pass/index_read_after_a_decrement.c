/*
 * Rule: ARR30-C
 * Status: PASS - The index is stepped down before the access
 * Reason: each access reads `i` after the decrement that precedes it in the
 * same block, so the largest index used is 3 for a 4-element array. Reading
 * the range at the block's entry, or the last `i = 4;` as the index's value,
 * names index 4, which the access never uses.
 */

void count_down_while(void)
{
    int a[4];
    int i = 4;
    while (i > 0) {
        i--;
        a[i] = 0;
    }
}

void count_down_do(void)
{
    int a[4];
    int i = 4;
    do {
        i--;
        a[i] = 0;
    } while (i > 0);
}

void step_down_once(void)
{
    int a[4];
    int i = 4;
    i--;
    a[i] = 0;
}

void subtract_once(void)
{
    int a[4];
    int i = 4;
    i -= 1;
    a[i] = 0;
}
