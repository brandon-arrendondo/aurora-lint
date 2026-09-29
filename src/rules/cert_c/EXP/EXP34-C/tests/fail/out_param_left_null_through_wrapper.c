/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * open_handle() forwards its out-parameter to lookup(), which stores NULL
 * when the name is unknown. Writing through `&h` says the callee stored
 * something, not that it stored a usable handle, and nothing tests `h`
 * before it is dereferenced.
 */
#include <string.h>

struct handle { int fd; };
static struct handle the_handle;

void lookup(const char *name, struct handle **out) {
    if (strcmp(name, "main") == 0)
        *out = &the_handle;
    else
        *out = 0;
}

void open_handle(const char *name, struct handle **out) {
    lookup(name, out);
}

int handle_fd(const char *name) {
    struct handle *h;
    open_handle(name, &h);
    return h->fd;
}
