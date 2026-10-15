/*
 * Rule: INT34-C
 * Status: PASS - a block-scope typedef defined in each preprocessor arm
 * Settings: data_model=lp64
 *
 * An #ifdef arm opens no scope, so the typedef in whichever arm is compiled
 * belongs to the function body and hides the file-scope 32-bit word. Both
 * arms make it 64 bits wide, so a shift by 40 is in range.
 */

typedef unsigned int word;

unsigned long long high_word(void)
{
#ifdef WIDE_WORDS
    typedef unsigned long long word;
#else
    typedef unsigned long long word;
#endif
    word w = 1;
    return w << 40;
}
