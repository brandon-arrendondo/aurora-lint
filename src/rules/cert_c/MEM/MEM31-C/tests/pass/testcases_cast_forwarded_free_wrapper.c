/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * The safe_free_wrapper_chain shape with a cast on the forwarding leg.
 * release_slot() frees nothing itself; it hands its own void** parameter to
 * backend_free() through a cast, so propagate_transitive_frees_param_pointees
 * only reaches release_slot if collect_param_passthroughs strips the cast
 * (task 1034, tools_sqc).
 */

#include <stdlib.h>

static void backend_free(unsigned char **raw) {
    if (raw && *raw) {
        free(*raw);
        *raw = NULL;
    }
}

static void release_slot(void **slot) {
    backend_free((unsigned char **)slot);
}

void use_buffer(void) {
    char *buf = malloc(32);
    if (!buf) {
        return;
    }
    release_slot((void **)&buf);
}
