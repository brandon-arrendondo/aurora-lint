#include <stddef.h>

/* The same tag, defined differently here: `sme` has a named type and its
 * `ie` is an integer. This file's definition is the one in scope, so the
 * other file's anonymous `sme` must not answer for it. */
struct sme_t {
    size_t ie;
};

struct S {
    struct sme_t sme;
};

size_t total(struct S *s, size_t n)
{
    return s->sme.ie + n;
}
