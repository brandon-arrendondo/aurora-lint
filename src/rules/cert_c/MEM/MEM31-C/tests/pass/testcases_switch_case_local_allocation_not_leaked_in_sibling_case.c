/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: PASS
 * Reason: An allocation made and freed entirely within one switch case must
 * not be reported against a return/goto in a SIBLING case that never
 * mentions it -- each case starts from the state the switch itself was
 * entered with, not from whatever an earlier case happened to leave
 * allocated. Modeled on a real dispatch-switch shape (lua's luaV_execute,
 * pure-ftpd's ftpd.c option parser) where an allocation local to one case
 * was previously reported against every return/goto in every other case of
 * the same switch.
 */

#include <stdlib.h>

void dispatch(int op, int flag) {
    switch (op) {
        case 1: {
            char *scratch = malloc(64);
            if (scratch == NULL) {
                return;
            }
            scratch[0] = 'x';
            free(scratch);
            break;
        }
        case 2:
            /* No allocation on this path at all -- must not be flagged for
             * "scratch" from case 1, which this case never touches. */
            if (flag) {
                return;
            }
            break;
        default:
            return;
    }
}
