/*
 * Rule: EXP34-C
 * Source: testcases (hostap caller-contract cohort)
 * Status: EXPECTED_FAIL - Known limitation, tracked by aurora_lint 1426.
 *         The relay sits in the TRUE branch of `!data`, where the pointer
 *         IS null. Companion to pass/testcases_short_circuit_caller_guard.c:
 *         crediting the mere presence of a dominating null test, rather than
 *         the branch it selects, would invert this answer and mask the
 *         defect.
 *
 *         Regressed by task 1418 (EXP34-C now reports only at the callee's
 *         own unguarded dereference, seeded from prescan's cross-file
 *         `callsite_param_null_states`, instead of also checking each call
 *         site's own full per-function CFG state). `sink`'s callee-side seed
 *         comes from prescan's `collect_early_return_null_guards`, which
 *         wrongly credits `data` NotNull for "the rest of the function"
 *         whenever an early-return guard's consequence contains a return
 *         anywhere in it -- here the risky call is the return's own argument
 *         expression, evaluated INSIDE the branch where `data` is null, not
 *         after it. General `local_states` bug, not EXP34-C-specific; fix
 *         belongs to 1426, not here.
 */

#include <stdio.h>

static int sink(const int *ptr)
{
    return *ptr;
}

int relay(void)
{
    int *data = NULL;

    if (!data)
        return sink(data);

    return 0;
}
