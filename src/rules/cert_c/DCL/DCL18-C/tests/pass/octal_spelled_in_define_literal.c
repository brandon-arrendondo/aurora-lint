/*
 * Rule: DCL18-C
 * Source: testcases
 * Status: PASS - Should not trigger DCL18-C violation
 *
 * No replacement list holds an octal constant: 0 is zero in any base, 0x10
 * is hexadecimal, and "0644" is a string literal.
 */

#define NONE 0
#define SIXTEEN 0x10
#define MODE_TEXT "0644" /* not 0644 */

int total(void)
{
    return NONE + SIXTEEN + (int)sizeof MODE_TEXT;
}
