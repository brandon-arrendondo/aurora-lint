/*
 * Rule: MEM30-C
 * Source: review regression
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: `destroy` frees `*hp` on every path but writes NULL back only
 * when `clear` is set. Called with 0, it leaves `o->h` pointing at the
 * freed block, and reading `o->h->fd` afterwards is a use after free. Only
 * a NULL write that follows the free on every path leaves the caller's
 * pointer NULL.
 */
#include <stdlib.h>

struct handle {
    int fd;
};

struct owner {
    struct handle *h;
};

static void destroy(struct handle **hp, int clear)
{
    free(*hp);
    if (clear)
        *hp = NULL;
}

int reopen(struct owner *o)
{
    destroy(&o->h, 0);
    return o->h->fd;
}
