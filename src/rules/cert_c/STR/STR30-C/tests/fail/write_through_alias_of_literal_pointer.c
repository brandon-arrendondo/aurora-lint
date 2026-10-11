/*
 * Rule: STR30-C
 * Source: synthetic
 * Status: FAIL - The alias points where s does: into the literal
 */

void func(void)
{
    char *s = "abc";
    char *alias = s;
    alias[0] = 'x';
}
