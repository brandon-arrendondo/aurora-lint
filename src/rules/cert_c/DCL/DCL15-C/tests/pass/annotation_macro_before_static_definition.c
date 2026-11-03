/*
 * Rule: DCL15-C
 * Source: regression
 * Status: PASS - a static function after an annotation macro is static
 *
 * `CHECK_RESULT` stands alone on the line before the definition, and the
 * file does not define it: it comes from a configuration header. The parser
 * read it as the function's type and stranded `unsigned long`, so the
 * function was taken for one without `static` and asked to be made static.
 */
CHECK_RESULT
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
