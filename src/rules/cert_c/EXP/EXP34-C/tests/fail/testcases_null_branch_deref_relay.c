/*
 * Rule: EXP34-C
 * Source: testcases (hostap caller-contract cohort)
 *
 * The relay sits in the TRUE branch of `!data`, where the pointer IS null.
 * Companion to pass/testcases_short_circuit_caller_guard.c: crediting the
 * mere presence of a dominating null test, rather than the branch it
 * selects, would invert this answer and mask the defect.
 *
 * Regressed by an earlier fix (EXP34-C now reports only at the callee's own
 * unguarded dereference, seeded from prescan's cross-file
 * `callsite_param_null_states`) and fixed by an earlier fix: two flat,
 * whole-function `local_states` sites -- `guarded_nonnull_after` (consulted
 * from `extract_init_state` while collecting the declaration's own state)
 * and `collect_early_return_null_guards` -- both credited a guarded
 * variable NotNull "for the rest of the function" whenever the guard's
 * consequence diverges, without checking that the consequence's own
 * expression (here, the return statement's argument) doesn't use the
 * variable while it is still null. Both now bail out via
 * `node_references_identifier` when the diverging branch itself references
 * the guarded variable.
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
