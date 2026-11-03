/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A store later in the loop reaches the next iteration's shift
 *
 * The store through `q` follows the shift in the loop body, so the first
 * iteration shifts by 3 and every later one by the unchecked value.
 */

int read_untrusted(void);

int masks(int count)
{
    int s = 3;
    int r = 0;
    int *q = &s;
    while (count--) {
        r |= 1 << s;
        *q = read_untrusted();
    }
    return r;
}
