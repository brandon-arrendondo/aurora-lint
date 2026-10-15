/*
 * Rule: INT34-C
 * Status: PASS - a hexadecimal constant too large for int is unsigned int
 * Settings: data_model=lp64
 *
 * `0xffffffff` does not fit a 32-bit int, so it is an unsigned int and its
 * precision is 32. An amount in [0, 31] is in range.
 */

unsigned int prefix_mask(unsigned int bits)
{
    if (bits >= 1 && bits <= 32) {
        return 0xffffffff << (32 - bits);
    }
    return 0;
}
