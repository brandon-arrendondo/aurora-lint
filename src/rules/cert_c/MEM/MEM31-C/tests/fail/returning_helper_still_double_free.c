/*
 * Rule: MEM31-C
 * Source: task_1076
 * Status: FAIL - Should trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: FAIL
 * Reason: The companion to task_1076's PASS case. A helper that is NOT marked
 * noreturn returns to its caller, so the branch falls through to the second
 * free() and the double free is real. Guards against the noreturn exemption
 * being applied to any called function rather than a declared-noreturn one.
 */

#include <stdlib.h>

static void log_error(const char *msg);

void returning_helper(int cond) {
    char *p = malloc(32);
    if (cond) {
        free(p);
        log_error("failed");
    }
    free(p);
}
