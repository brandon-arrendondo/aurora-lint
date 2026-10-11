/*
 * Rule: STR30-C
 * Source: synthetic
 * Status: PASS - The element written was reassigned to a buffer first
 */

void mark(char *buf)
{
    char *names[2] = {"a", "b"};
    names[0] = buf;
    names[0][0] = 'z';
}
