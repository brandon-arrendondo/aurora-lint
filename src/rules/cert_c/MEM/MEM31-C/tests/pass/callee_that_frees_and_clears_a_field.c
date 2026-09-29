/*
 * Rule: MEM31-C
 * Source: real-world (hostap: wpas_dpp_deinit() frees and clears a field
 *         that the caller then releases again)
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: `session_deinit` frees `s->label` and writes NULL back, so the
 * caller's own free() of the field releases NULL. A field a callee frees is
 * credited for leak purposes only; it cannot back a double-free accusation.
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

void session_reset(struct session *s)
{
    session_deinit(s);
    free(s->label);
    s->label = NULL;
}
