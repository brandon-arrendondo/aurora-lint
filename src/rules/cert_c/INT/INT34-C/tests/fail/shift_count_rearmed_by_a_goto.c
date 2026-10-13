/*
 * Rule: INT34-C
 * Status: FAIL - a jump back into the loop re-enters it with a count of 40
 * Settings: data_model=lp64
 *
 * The count is stepped down from 4, but `i = 40; goto again;` restarts the
 * loop, whose first shift is then by 39.
 */

unsigned int rearm_by_goto(unsigned int x, int r)
{
    unsigned int i = 4;
    unsigned int acc = 0;
again:
    do {
        i -= 1;
        acc |= x >> i;
        if (r == 7) {
            i = 40;
            goto again;
        }
    } while (i);
    return acc;
}
