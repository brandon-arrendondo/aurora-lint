/*
 * Rule: STR30-C
 * Source: synthetic
 * Status: FAIL - On the second iteration p points into the literal
 */

void func(char *buf)
{
    char *p = buf;
    for (int i = 0; i < 2; i++) {
        p[0] = 'z';
        p = "lit";
    }
}
