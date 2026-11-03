/*
 * Rule: DCL15-C
 * Source: regression
 * Status: PASS - a static function after an annotation macro is static
 *
 * The annotation macro carries a line comment of its own. The comment is
 * not a word of the declaration, so the macro, not the comment, is what
 * the parser took for the type, and the function keeps its `static`.
 */
CHECK_RESULT // the caller must use the sum
static unsigned long total(const unsigned long *v, int n)
{
    unsigned long t = 0;
    int i;
    for (i = 0; i < n; i++) {
        t += v[i];
    }
    return t;
}

int main(void)
{
    unsigned long v[4] = {1, 2, 3, 4};
    return (int)total(v, 4);
}
