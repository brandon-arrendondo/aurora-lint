/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The size of an int is not known under ISO C's widths
 * Settings: data_model=iso
 *
 * sizeof(buf) - 1 is no known constant, so no index is claimed for it.
 * Read as an element count, it was 7, which is in bounds only by luck.
 */

int last(void)
{
    int buf[8] = {0};
    return buf[sizeof(buf) - 1];
}
