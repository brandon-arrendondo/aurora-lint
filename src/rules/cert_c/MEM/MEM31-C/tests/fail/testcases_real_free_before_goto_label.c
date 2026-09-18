/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * Counterpart to testcases_name_guess_survives_goto_label.c: when the free
 * before the jump is real -- a callee whose body releases the parameter
 * itself -- the label's release is a possible double free on that path
 * and must still be reported.
 */
#include <stdlib.h>

struct handle {
    char *scheme;
};

/* `_free` suffix AND a body that frees `h` itself. */
static void handle_free(struct handle *h) {
    free(h->scheme);
    free(h);
}

static int handle_set(struct handle *h, const char *url) {
    if (url == NULL) {
        handle_free(h);
        return 1;
    }
    return 0;
}

char *rewrite(const char *url) {
    struct handle *u = malloc(sizeof(*u));
    if (u == NULL)
        return NULL;
    u->scheme = NULL;
    if (handle_set(u, url))
        goto error;
    return NULL;
error:
    free(u); /* VIOLATION: handle_set already released u on this path */
    return NULL;
}
