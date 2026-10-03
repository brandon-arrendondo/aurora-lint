/*
 * Rule: INT32-C
 * Source: regression
 * Status: FAIL - the project declares a 16-bit int
 * Settings: data_model=lp64, int_bits=16
 *
 * The lp64 preset loads int_bits = 32, where 1 << 27 fits. A project that
 * writes int_bits = 16 under [environment] overrides the preset's value
 * whatever the order of the lines, and the shift no longer fits an int.
 */

unsigned int flag_bit(unsigned int type) {
    return (unsigned int)(type | (1 << 27)); /* VIOLATION */
}
