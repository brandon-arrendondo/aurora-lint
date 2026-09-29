/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: EXPECTED FAIL - Known limitation: the double free is real, and
 * MEM31-C does not report it.
 *
 * Counterpart to testcases_name_guess_survives_goto_label.c. `handle_set`
 * releases `h` on one path only, the one where it returns 1, and the caller
 * reaches the label's free() only through that result. Proving the double
 * free needs that correlation between the callee's result and its release.
 * The summary records only that the release MAY happen, and a MAY release
 * cannot back an accusation: the same fact, read as a free, reported every
 * later reply to a client that valkey's addReply* closes only on error.
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
