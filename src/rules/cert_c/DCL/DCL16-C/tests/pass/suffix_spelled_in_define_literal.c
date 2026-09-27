/*
 * Rule: DCL16-C
 * Source: testcases
 * Status: PASS - Should not trigger DCL16-C violation
 *
 * The replacement lists' literals use uppercase suffixes; the lowercase
 * ones are inside a string literal and a comment.
 */

#define BIG 0xffffffffULL
#define LABEL "limit 10l" /* was 10l */

unsigned long long big(void)
{
    return BIG + sizeof LABEL;
}
