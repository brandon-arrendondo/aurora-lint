/*
 * Rule: INT34-C
 * Status: PASS - While loop bounds shift via (mask >> bi) != 0 pattern
 */


unsigned int count_bits(unsigned int mask) {
    unsigned int count = 0;
    unsigned int bi = 0;
    while ((mask >> bi) != 0u) {
        if ((mask >> bi) & 1u) {
            count++;
        }
        bi++;
    }
    return count;
}
