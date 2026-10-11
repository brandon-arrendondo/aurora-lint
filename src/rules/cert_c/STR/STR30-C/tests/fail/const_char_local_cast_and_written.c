/*
 * Rule: STR30-C
 * Source: synthetic
 * Status: FAIL - A pointer to const characters is treated as a literal
 *
 * CERT: "a pointer to (or array of) const characters must be treated as a
 * string literal". Casting the const away does not make the target
 * writable.
 */

void func(void)
{
    const char *c = "lit";
    char *nc = (char *)c;
    nc[0] = 'y';
}
