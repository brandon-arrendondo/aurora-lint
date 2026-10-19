/*
 * Rule: MSC13-C
 * Source: synthetic
 * Status: FAIL - a string literal's address is not a default value, and every path overwrites it before a read
 */

int f(int c)
{
    const char *s = "none";
    s = c ? "a" : "b";
    return s[0];
}
