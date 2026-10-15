/*
 * Rule: INT34-C
 * Status: FAIL - 31 is not below the precision of a 32-bit signed int
 * Settings: data_model=lp64
 *
 * A signed int of 32 bits has 31 value bits. CERT bounds the amount by the
 * precision, so `1 << 31` is reported where `1u << 31` is not.
 */

int sign_bit(void)
{
    return 1 << 31;
}
