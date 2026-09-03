/*
 * Rule: ARR38-C
 * Source: curl lib/altsvc.c altsvc_create (task 746)
 * Status: PASS - Should NOT trigger ARR38-C violation
 *
 * `is_potentially_user_controlled_in_source` never looked at the destination
 * buffer, so any (buffer, length) parameter pair looked "unvalidated" even
 * when the destination was allocated, in the same function, from a size
 * expression that itself mentions the flagged length. Here `as->src.host`
 * points into a block sized as `sizeof(struct thing) + hlen + 1`, so the
 * `hlen`-byte memcpy into it provably fits.
 */

#include <stdlib.h>
#include <string.h>

struct host_pair {
    char *host;
};

struct thing {
    struct host_pair src;
};

struct thing *make_thing(const char *srchost, size_t hlen) {
    struct thing *as;

    as = curlx_calloc(1, sizeof(struct thing) + hlen + 1);
    if (!as)
        return NULL;

    as->src.host = (char *)as + sizeof(struct thing);
    memcpy(as->src.host, srchost, hlen);

    return as;
}
