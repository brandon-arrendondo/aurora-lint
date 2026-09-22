/*
 * Rule: ENV30-C
 * Source: aurora_lint 1433
 * Status: PASS - Should NOT trigger ENV30-C violation
 */

/*
 * A node's source range includes its comments, so the text scan this
 * replaced read the mention of strchr below as a call and recorded the
 * strdup'd COPY as a pointer into the environment string -- the same
 * mechanism 1428 fixed for the protected functions themselves.
 */

#include <stdlib.h>
#include <string.h>

void copy_then_edit(void) {
    char *env = getenv("PATH");

    if (env == NULL) {
        return;
    }

    char *owned = strdup(
        /* a separator search would be strchr(env, ':') */
        env);

    if (owned != NULL) {
        /* COMPLIANT: owned is this program's own copy, not the
         * environment string */
        strcpy(owned, "/usr/bin");
        free(owned);
    }
}
