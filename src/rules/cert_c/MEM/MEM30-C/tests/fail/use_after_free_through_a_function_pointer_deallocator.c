/*
 * Rule: MEM30-C
 * Source: custom
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: the MEM31-C fix for function-pointer deallocators, at the
 * opposite polarity.
 * sqlite's `sqlite3_free(void *p)` releases the block through
 * `sqlite3GlobalConfig.m.xFree(p)`, a call through a function POINTER that
 * no summary can follow, so its `frees_params`, `frees_param_pointees` and
 * `frees_param_fields` are all empty. A present summary is trusted over a
 * name shape, so that emptiness refuted the name and the call
 * below stopped being a free at all -- which for MEM31-C meant a leak it
 * wrongly reported, and here means a use-after-free it never got to see.
 *
 * The free is credited on the name, so the finding carries
 * requires_manual_review: the reader is told the release is an inference
 * from a spelling, not a body that was read.
 */

#include <stdlib.h>

struct mem_methods {
    void (*xFree)(void *);
};

struct global_config {
    struct mem_methods m;
};

static struct global_config g_config;

void amalg_free(void *p)
{
    if (p == 0) {
        return;
    }
    g_config.m.xFree(p);
}

int read_after_release(void)
{
    char *a = malloc(64);

    if (a == NULL) {
        return 1;
    }
    a[0] = 'x';
    amalg_free(a);

    /* VIOLATION: `a` was released by the wrapper above */
    return a[0];
}
