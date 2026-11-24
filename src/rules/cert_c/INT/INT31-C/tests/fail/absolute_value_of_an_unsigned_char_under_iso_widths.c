/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - under ISO widths an unsigned char may be as wide as an int
 * Settings: data_model=iso
 * Expect: count=2
 *
 * ISO C sets no upper bound on CHAR_BIT (C11 5.2.4.2.1), so an unsigned
 * char may be as wide as an int and hold values that convert to INT_MIN.
 * `abs(d) <= 100` then bounds nothing, and `d` may still exceed
 * SCHAR_MAX: the conversion is reported both as unsigned to signed and as
 * narrowing. A direct test of `d` itself bounds it either way.
 */
#include <stdlib.h>

void use(signed char);

void guarded_by_abs(unsigned char d)
{
    if (d > 200)
        return;
    if (abs(d) <= 100)
        use((signed char)d);
}

void guarded_directly(unsigned char d)
{
    if (d > 100)
        return;
    use((signed char)d);
}
