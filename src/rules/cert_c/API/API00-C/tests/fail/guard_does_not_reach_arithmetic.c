/*
 * Rule: API00-C
 * Source: real-world (task 739)
 * Status: FAIL - Should trigger API00-C violation
 */

/*
 * The counterpart to tests/pass/guard_spellings_bound_parameter.c. Widening
 * what counts as a validation check must not turn into "a comparison appears
 * somewhere in this function". In each function below the parameter IS
 * compared, but the comparison does not reach the arithmetic, so the arithmetic
 * is still unvalidated.
 */

#include <stddef.h>

/* The guard runs AFTER the arithmetic it would have protected. */
int check_too_late(int n)
{
    int doubled = n * 2;
    if (n < 0)
        return 0;
    return doubled;
}

/* The guard is in a sibling branch the arithmetic is not reached through. */
int guarded_other_branch(int flag, int n)
{
    if (flag) {
        if (n < 100)
            return n;
        return 0;
    }
    return n + 1;
}

/* The comparison IS the arithmetic: `off + n` can wrap before the > is
 * evaluated, so the check cannot have bounded `n` beforehand. */
size_t sum_checked_by_itself(size_t off, size_t n, size_t limit)
{
    if (off + n > limit)
        return 0;
    return off;
}
