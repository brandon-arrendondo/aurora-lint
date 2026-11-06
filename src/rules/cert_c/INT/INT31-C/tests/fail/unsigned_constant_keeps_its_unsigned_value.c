/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - An unsigned constant is its value modulo its type's width
 * Settings: data_model=lp64
 * Expect: count=2
 *
 * `~0U` and `0U - 1` are UINT_MAX, not -1: no `int` holds it, and no
 * `unsigned short` does either. An `unsigned long` does.
 */

void sink(long);

void constants(void)
{
    int all = ~0U;               /* Expect: here */
    unsigned short wrap = 0U - 1; /* Expect: here */
    unsigned long fine = ~0U;
    sink(all + wrap + (long)fine);
}
