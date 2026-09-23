/*
 * Rule: MEM30-C
 * Source: task 1360 (companion to pass/task_1360_noreturn_branch_has_no_join_edge.c)
 * Status: FAIL - Should trigger MEM30-C violation
 * Reason: Only a call that provably never returns ends a branch. A branch
 *         that frees and then calls an ordinary function -- one that does
 *         return, however final its name sounds -- rejoins, and the use and
 *         second free after the `if` are reachable with the pointer freed.
 */

#include <stdio.h>
#include <stdlib.h>

void report_and_continue(const char *msg);
void use(char *p);

int ordinary_call_in_then(int rc)
{
    char *p = malloc(16);
    if (rc != 0) {
        free(p);
        report_and_continue("bad");   /* returns; the branch rejoins */
    }
    use(p);        /* VIOLATION: use-after-free when rc != 0 */
    free(p);       /* VIOLATION: double free when rc != 0 */
    return 0;
}
