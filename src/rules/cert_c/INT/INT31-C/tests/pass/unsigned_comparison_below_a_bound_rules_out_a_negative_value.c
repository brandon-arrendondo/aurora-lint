/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: PASS - A signed value below an unsigned bound is not negative
 * Settings: data_model=iso
 *
 * `x < 256u` converts `x` to unsigned, where a negative value reads as a
 * large one, so where it is true `x` lies between 0 and 255.
 */

void sink(int);

void below_unsigned(int x)
{
    unsigned char c = 0;
    if (x < 256u) {
        c = (unsigned char)x;
    }
    sink(c);
}
