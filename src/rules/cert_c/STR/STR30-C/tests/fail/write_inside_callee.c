/*
 * Rule: STR30-C
 * Source: synthetic
 * Status: FAIL - The callee's body writes through the parameter passed a literal
 */

static void upcase_first(char *p)
{
    p[0] = 'U';
}

void func(void)
{
    upcase_first("hello");
}
