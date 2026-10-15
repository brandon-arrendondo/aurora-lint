/*
 * Rule: INT34-C
 * Status: PASS - a typedef name is the one visible where the object is
 * declared
 * Settings: data_model=lp64
 *
 * The block's own typedef hides the file-scope one, so w is 64 bits wide and
 * a shift by 40 is in range.
 */

typedef unsigned int word;

unsigned long long high_word(void)
{
    typedef unsigned long long word;
    word w = 1;
    return w << 40;
}
