/*
 * Rule: INT34-C
 * Status: FAIL - a later trip round the loop shifts by 40
 * Settings: data_model=lp64
 *
 * `i = 3;` before the loop is the count only on the first trip: the body
 * stores 40 and continues, and the next trip shifts by that.
 */

unsigned int rearm_while(unsigned int x, int c, int k)
{
    unsigned int i = 3;
    unsigned int acc = 0;
    while (k--) {
        acc |= x >> i;
        if (c) {
            i = 40;
            continue;
        }
        i = 3;
    }
    return acc;
}
