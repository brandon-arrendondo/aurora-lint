/*
 * Rule: MEM31-C
 * Source: task 1089
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * Reason: `check_for_return_macro` treats any callee whose name contains
 * RETURN/EXIT/ABORT as a possible early return out of the function and
 * reports every still-live allocation as leaked. When that callee is
 * actually a noreturn process-exit helper, nothing leaks -- the process is
 * ending and the OS reclaims the allocation. Modelled on pure-ftpd's
 * `die_mem()`, whose name-heuristic match produced exactly this shape.
 */

#include <stdlib.h>

_Noreturn void exit_with_error(const char *msg);
int config_is_bad(void);

void load_config(void) {
    char *buf = malloc(1024);
    if (buf == NULL) {
        return;
    }

    if (config_is_bad()) {
        /* Never returns: the process ends here, so `buf` is not leaked. */
        exit_with_error("bad config");
    }

    buf[0] = '\0';
    free(buf);
}
