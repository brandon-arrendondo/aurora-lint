/*
 * Rule: INT34-C
 * Status: PASS - a block-scope typedef that follows a case label
 * Settings: data_model=lp64
 *
 * A case label opens no scope: the typedef belongs to the switch body and
 * hides the file-scope 32-bit word, so w is 64 bits wide and a shift by 40
 * is in range.
 */

typedef unsigned int word;

unsigned long long high_word(int kind)
{
    switch (kind) {
    case 1:;
        typedef unsigned long long word;
        word w = 1;
        return w << 40;
    }
    return 0;
}
