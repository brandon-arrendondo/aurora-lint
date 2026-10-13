/*
 * Rule: INT34-C
 * Status: PASS - every count the loop stores is below 32
 * Settings: data_model=lp64
 */

unsigned int reset_within_width(unsigned int x, int c, int k)
{
    unsigned int i = 3;
    unsigned int acc = 0;
    while (k--) {
        acc |= x >> i;
        if (c) {
            i = 7;
            continue;
        }
        i = 3;
    }
    return acc;
}
