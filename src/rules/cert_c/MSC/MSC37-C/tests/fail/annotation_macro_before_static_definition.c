/*
 * Rule: MSC37-C
 * Source: regression
 * Status: FAIL - a non-void function after an annotation macro can end
 *         without a return
 *
 * `CHECK_RESULT` stands alone on the line before the definition. The parser
 * read it as the function's type and stranded `int`, so the function began
 * on the macro's line. With the macro read as the annotation it is, the
 * function is `static int level(int v)` and its missing return is reported
 * where the function begins.
 */
#define CHECK_RESULT __attribute__((__warn_unused_result__))

CHECK_RESULT
static int level(int v) /* Expect: here */
{
    if (v > 0) {
        return 1;
    }
}

int api(int v)
{
    return level(v);
}
