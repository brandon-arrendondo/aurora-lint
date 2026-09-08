/*
 * Rule: EXP34-C
 * Source: testcases (hostap caller-contract cohort)
 * Status: PASS - every call site guards the pointer with a short-circuit
 *         test, so `sink`'s parameter is non-null wherever it is reached and
 *         its unchecked dereference honours the caller's contract.
 *
 * Both shapes come from hostap wpa_supplicant/interworking.c, where
 * cred_prio_cmp dereferences a parameter no caller can pass null:
 *
 *   :1457  if (selected == NULL || is_excluded ||
 *              cred_prio_cmp(selected, cred) < 0)     -- later disjunct
 *   :1798  if (cred_rc && (cred == NULL ||
 *              cred_prio_cmp(cred_rc, cred) >= 0))    -- later conjunct
 *
 * The guard is INSIDE the condition holding the call, so a whole-function
 * state table cannot express it: that table carries one state per variable
 * and the allocation really may fail. Note the declaration is deliberately
 * NOT followed directly by the guard -- an adjacent diverging null-check is
 * already credited by a separate, narrower path, and crediting it here would
 * make this fixture pass without exercising the per-site query at all.
 */

#include <stdlib.h>

static int sink(const int *ptr)
{
    return *ptr;
}

int relay_or(void)
{
    int *selected = malloc(sizeof(int));
    int rc = 0;

    /* Reaching the second disjunct means the null test was false. */
    if (selected == NULL || sink(selected) < 0)
        rc = -1;

    free(selected);
    return rc;
}

int relay_and(void)
{
    int *cred_rc = malloc(sizeof(int));
    int rc = 0;

    /* Reaching the right conjunct means cred_rc was truthy. */
    if (cred_rc && sink(cred_rc) >= 0)
        rc = 1;

    free(cred_rc);
    return rc;
}
