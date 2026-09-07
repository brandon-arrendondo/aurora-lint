/*
 * Rule: API00-C
 * Source: custom
 * Status: PASS - Should NOT trigger API00-C violation
 * Description: Case 1's breadth was partly deliberate -- it meant to accept
 * `if (isNullOrEmpty(ptr)) return;`, which condition_tests_null rejects by
 * design. Task 902 kept the call form but resolved it instead of assuming it:
 * the callee has to be one whose own summary says it null-checks the argument
 * it was handed at that position, which is what tells `is_null_or_empty(ptr)`
 * apart from `chdir(base)` in tests/fail/
 * early_exit_condition_names_the_param.c.
 */

int is_null_or_empty(const char *s)
{
    if (!s)
        return 1;
    return s[0] == 0;
}

int use_it(const char *ptr)
{
    if (is_null_or_empty(ptr))
        return -1;
    return ptr[0];
}
