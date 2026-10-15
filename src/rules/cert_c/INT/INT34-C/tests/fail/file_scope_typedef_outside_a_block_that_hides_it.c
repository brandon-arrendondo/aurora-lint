/*
 * Rule: INT34-C
 * Status: FAIL - the block-scope typedef is out of scope where w is declared
 * Settings: data_model=lp64
 *
 * The inner typedef names a 64-bit type only inside its own block. Outside
 * it, word is the file-scope 32-bit unsigned int, and a shift by 40 is
 * undefined.
 */

typedef unsigned int word;

unsigned int low_word(void)
{
    {
        typedef unsigned long long word;
    }
    word w = 1;
    return w << 40; /* VIOLATION */
}
