/*
 * Rule: DCL18-C
 * Source: testcases
 * Status: FAIL - Should trigger DCL18-C violation
 *
 * A replacement list's literals are literals like any other: 0644 is
 * octal wherever the macro expands.
 */

#define MODE 0644 /* VIOLATION */

int mode(void)
{
    return MODE;
}
