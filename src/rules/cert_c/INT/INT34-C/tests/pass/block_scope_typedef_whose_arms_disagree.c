/*
 * Rule: INT34-C
 * Status: PASS - preprocessor arms that give a typedef different widths
 * Settings: data_model=lp64
 *
 * Which arm is compiled is not known, so neither width is assumed for w,
 * and a constant amount below the width of every standard integer type is
 * not judged against either.
 */

typedef unsigned int word;

unsigned long long high_word(void)
{
#ifdef WIDE_WORDS
    typedef unsigned long long word;
#else
    typedef unsigned short word;
#endif
    word w = 1;
    return w << 40;
}
