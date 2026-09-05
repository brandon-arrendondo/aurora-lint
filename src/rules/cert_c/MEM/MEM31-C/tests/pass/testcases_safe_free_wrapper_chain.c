/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * A free-through-void** wrapper, one layer deeper. release_slot() does not
 * free anything itself; it forwards its own void** parameter to safe_free(),
 * which frees the pointee. The summary fact has to reach release_slot
 * transitively (propagate_transitive_frees_param_pointees) or the caller's
 * buf looks unmatched.
 */

#include <stdlib.h>

static void safe_free(void **ptr) {
    if (ptr && *ptr) {
        free(*ptr);
        *ptr = NULL;
    }
}

static void release_slot(void **slot) {
    safe_free(slot);
}

void use_buffer(void) {
    char *buf = malloc(32);
    if (!buf) {
        return;
    }
    release_slot((void **)&buf);
}
