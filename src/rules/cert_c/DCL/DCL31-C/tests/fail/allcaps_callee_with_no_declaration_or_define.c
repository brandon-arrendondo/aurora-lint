/*
 * Rule: DCL31-C
 * Source: testcases
 * Status: FAIL - Should trigger DCL31-C violation
 *
 * `COMPUTE_TOTAL` is spelled like a macro, but no `#define` names it and
 * nothing declares it, so the call relies on an implicit declaration. The
 * spelling alone does not make it a macro.
 */

int total(int a, int b)
{
    return COMPUTE_TOTAL(a, b);  /* VIOLATION: implicitly declared */
}
