/*
 * Rule: DCL15-C
 * Source: regression
 * Status: PASS - a static function after an annotation macro is static
 *
 * As with an annotation macro that opens the file, but a line comment
 * stands between the declaration before it and the macro. The comment does
 * not change where a declaration may begin, so the macro still begins this
 * one and the function keeps its `static`.
 */
int calls;
// Sums the first n values.
CHECK_RESULT
static unsigned long total(const unsigned long *v, int n)
{
    unsigned long t = 0;
    int i;
    for (i = 0; i < n; i++) {
        t += v[i];
    }
    calls++;
    return t;
}

int main(void)
{
    unsigned long v[4] = {1, 2, 3, 4};
    return (int)total(v, 4);
}
