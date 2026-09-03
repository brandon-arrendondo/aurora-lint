/*
 * Rule: ARR38-C
 * Source: task 746 companion regression
 * Status: FAIL - Should trigger ARR38-C violation
 *
 * Companion to dest_sized_by_alloc_mentioning_identifier.c (pass): the
 * destination is member-access shaped (`as->src.host`), but the base `as`
 * is allocated with a FIXED size that never mentions `hlen`, so the copy is
 * not provably bounded. The dest-buffer check added for task 746 must not
 * over-suppress just because the destination happens to be a struct field.
 */

#include <stdlib.h>
#include <string.h>

struct host_pair {
    char *host;
};

struct thing {
    struct host_pair src;
};

struct thing *make_thing_bad(const char *srchost, size_t hlen) {
    struct thing *as;

    as = calloc(1, sizeof(struct thing));
    if (!as)
        return NULL;

    as->src.host = malloc(10);
    memcpy(as->src.host, srchost, hlen);

    return as;
}
