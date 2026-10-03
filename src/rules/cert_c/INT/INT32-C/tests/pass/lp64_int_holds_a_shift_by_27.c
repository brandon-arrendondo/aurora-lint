/*
 * Rule: INT32-C
 * Source: regression
 * Status: PASS - the lp64 preset's 32-bit int
 * Settings: data_model=lp64
 *
 * The counterpart of the override fixture: with nothing overridden, the lp64
 * preset's int_bits = 32 holds 1 << 27.
 */

unsigned int flag_bit(unsigned int type) {
    return (unsigned int)(type | (1 << 27));
}
