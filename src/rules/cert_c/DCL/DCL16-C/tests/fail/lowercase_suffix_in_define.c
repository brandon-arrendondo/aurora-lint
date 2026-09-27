/*
 * Rule: DCL16-C
 * Source: testcases
 * Status: FAIL - Should trigger DCL16-C violation
 *
 * A replacement list's literals are literals like any other: each of these
 * lowercase suffixes reads like a 1. The comment inside SCALE's body is
 * white space.
 */

#define BIG 0xffffffffull /* VIOLATION */
#define SCALE(x) ((x) /* per unit */ * 1000l) /* VIOLATION */

unsigned long long big(void)
{
    return BIG + (unsigned long long)SCALE(2);
}
