/*
 * Rule: INT34-C
 * Status: PASS - a shift in an #if or #elif condition
 * Settings: data_model=lp64
 *
 * The preprocessor evaluates a condition in intmax_t (C11 6.10.1p4), so
 * there is no int operand for the amount to exceed: 1 << 40 there is a
 * 64-bit shift.
 */

#if (1 << 40) > 0
#define HAVE_WIDE_INTMAX 1
#endif

#if defined(CONFIG_SMALL) && ((1 << 31) != 0)
#define SIGN_BIT_FITS 1
#elif (1 << 33) > 0
#define SIGN_BIT_FITS 2
#endif

int wide_intmax(void)
{
    return HAVE_WIDE_INTMAX;
}
