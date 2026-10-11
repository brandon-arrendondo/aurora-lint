/*
 * Rule: STR30-C
 * Source: synthetic
 * Status: FAIL - Element 0 is reassigned, element 1 still holds a literal
 */

void mark(char *buf)
{
    char *names[2] = {"a", "b"};
    names[0] = buf;
    names[1][0] = 'z';
}
