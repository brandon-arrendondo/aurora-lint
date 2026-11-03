/*
 * Rule: DCL40-C
 * Source: regression
 * Status: PASS - an annotation macro on the line before a static prototype
 *         is not read as the prototype's type
 *
 * `CHECK_RESULT` expands to an attribute or to nothing. The parser read it as
 * the type of the prototype, took `unsigned` for the declarator and lost the
 * rest, so the prototype and the definition below, which agree exactly, were
 * reported as returning `char` and `unsigned char`.
 */
#define CHECK_RESULT __attribute__((__warn_unused_result__))

CHECK_RESULT
static unsigned char *pick(unsigned char *a, unsigned char *b);

int api(unsigned char *a, unsigned char *b)
{
    return *pick(a, b);
}

static unsigned char *pick(unsigned char *a, unsigned char *b)
{
    return a ? a : b;
}
