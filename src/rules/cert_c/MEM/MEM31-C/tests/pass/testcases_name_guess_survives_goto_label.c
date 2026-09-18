/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * The goto-path form of testcases_named_deallocator_with_body_frees_only_
 * fields.c: a wrapper credited with freeing its parameter on a callee's
 * NAME alone (`reset_fields(h)` frees fields of `h`, not `h`), then a
 * `goto error` to a label that releases the handle for real. The credit
 * was a guess before the jump and is still a guess at the label; the
 * label's own release is the one real free, not a "possible double free
 * on a path that jumps to this label". curl's tool_xattr.c
 * (`curl_url_set(u, ...)` then `error: curl_url_cleanup(u)`) and
 * tool_operhlp.c were this.
 */
#include <stdlib.h>

struct handle {
    char *scheme;
    char *host;
};

/* `free_` prefix, body frees fields only. */
static void free_urlparts(struct handle *h) {
    free(h->scheme);
    h->scheme = NULL;
    free(h->host);
    h->host = NULL;
}

static int handle_set(struct handle *h, const char *url) {
    free_urlparts(h);
    if (url == NULL)
        return 1;
    h->scheme = malloc(8);
    return h->scheme == NULL;
}

char *rewrite(const char *url) {
    struct handle *u = malloc(sizeof(*u));
    char *out = NULL;
    if (u == NULL)
        return NULL;
    u->scheme = NULL;
    u->host = NULL;
    if (handle_set(u, url))
        goto error;
    out = malloc(16);
    if (out == NULL)
        goto error;
    free_urlparts(u);
    free(u);
    return out;
error:
    free_urlparts(u);
    free(u);
    return NULL;
}
