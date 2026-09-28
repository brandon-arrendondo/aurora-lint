/*
 * Rule: DCL18-C
 * Source: testcases
 * Status: PASS - Should not trigger DCL18-C violation
 *
 * The table rows pass byte digits to V, which pastes them into one
 * hexadecimal constant: 03, 08 and 0D are spelled into 0xC6080D03, never
 * read as integer constants of their own.
 */

#define V(a, b, c, d) 0x##a##b##c##d
#define TABLE V(C6, 08, 0D, 03), V(F8, 7C, 7C, 84)

static const unsigned table[] = { TABLE };

unsigned first(void)
{
    return table[0];
}
