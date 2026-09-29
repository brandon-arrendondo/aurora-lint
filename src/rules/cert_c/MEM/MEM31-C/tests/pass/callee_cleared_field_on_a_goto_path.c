/*
 * Rule: MEM31-C
 * Source: real-world (hostap: wpas_group_formation_completed() on the path
 *         that jumps to `out`, then os_free(wpa_s->go_params) at the label)
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: `session_deinit` frees `s->label` and writes NULL back. The
 * path that calls it jumps to `out`, where the field is freed again: a free
 * of NULL. A field a callee frees is credited for leak purposes only, on
 * every path into a label as on the path that made the call.
 */
#include <stdlib.h>

struct session {
    char *label;
    int active;
};

void session_deinit(struct session *s)
{
    s->active = 0;
    free(s->label);
    s->label = NULL;
}

void session_finish(struct session *s, int failed)
{
    if (failed) {
        session_deinit(s);
        goto out;
    }
    s->active = 2;
out:
    free(s->label);
    s->label = NULL;
}
