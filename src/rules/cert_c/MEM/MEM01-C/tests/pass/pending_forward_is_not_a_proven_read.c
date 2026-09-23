/*
 * Rule: MEM01-C
 * Source: custom (mirrors EXP33-C's task 1437 shape)
 * Status: PASS - Should NOT trigger MEM01-C violation
 * Description: `reinit` dereferences `pbuf` (a genuine read) AND forwards it
 * to `refill`, whose own write status this translation unit cannot resolve
 * because it forwards again to an undefined `external_refill`.
 * `credit_modifies_params` deliberately withholds a parameter from
 * `modifies_params` while that obligation is unresolved, parking it in
 * `modifies_params_pending` -- an open question, not a proven negative.
 *
 * Before aurora_lint 1459, build_read_only_params read that omission as
 * proof, so `pbuf` came back read-only and `reinit(&buf)` after the free was
 * reported as a use of the freed pointer. Companion to the indirect-call
 * case in task_1459_indirect_forward_is_not_a_proven_read.c; the plain
 * read-only callee in fail/testcases_use_after_free.c must stay flagged.
 */

#include <stdlib.h>

static void refill(char **pbuf)
{
    external_refill(pbuf);
}

static int reinit(char **pbuf)
{
    if (*pbuf == NULL) {
        return -1;
    }
    refill(pbuf);
    return 0;
}

void use_buffer(void)
{
    char *buf = malloc(64);

    if (buf == NULL) {
        return;
    }
    free(buf);
    reinit(&buf);
}
