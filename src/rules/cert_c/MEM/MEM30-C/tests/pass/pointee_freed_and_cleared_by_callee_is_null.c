/*
 * Rule: MEM30-C
 * Source: real-world (hostap: nl_destroy_handles(&bss->nl_mgmt) frees the
 *         handle and writes NULL back through its argument)
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: `destroy_handle` frees `*handle` and then sets it to NULL, so
 * after the call the caller's field is NULL, not dangling. Testing it
 * afterwards reads no freed memory.
 */
#include <stdlib.h>

struct handle {
    int fd;
};

struct owner {
    struct handle *h;
};

static void destroy_handle(struct handle **handle)
{
    if (*handle == NULL)
        return;
    free(*handle);
    *handle = NULL;
}

int reopen(struct owner *o)
{
    destroy_handle(&o->h);
    if (o->h != NULL)
        return o->h->fd;
    o->h = malloc(sizeof(*o->h));
    if (o->h == NULL)
        return -1;
    o->h->fd = 0;
    return 0;
}
