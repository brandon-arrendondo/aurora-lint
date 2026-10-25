/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: PASS - a size_t size followed by a flag
 *
 * The first argument of each call is the size, and it is size_t: the
 * flags after it are not sizes, so neither is reported as one.
 */
#include <stddef.h>
#include <string.h>

struct entry { int key; };

void *xalloc(size_t size, int nFlags);

char *copy_name(const char *s, int nFlags) {
    return xalloc(strlen(s) + 1, nFlags);
}

void *make_entries(size_t count, int nFlags) {
    return xalloc(sizeof(struct entry) * count, nFlags);
}
