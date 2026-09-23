/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: A call runs and returns BEFORE its result is bound. For a
 * callee that releases its argument and hands back a fresh block under the
 * SAME name -- hostap's `extra_ies = p2p_pasn_service_hash(p2p, extra_ies)`
 * in src/p2p/p2p.c -- that order is the whole answer: the name ends up on a
 * NEW block, so the later free is not a double free. Processing the
 * assignment before the call let the rebind clear the freed mark and the call
 * then re-applied it to the new block. An earlier fix; the ordering regressed in
 * 14f1d004 and this pins it.
 */

#include <stdlib.h>

static char *rehash(char *old) {
    char *n = malloc(64);

    if (!n) {
        return NULL;
    }
    free(old);
    return n;
}

extern char *make_buf(void);

int reassign_same_name(void) {
    char *buf = make_buf();

    if (!buf) {
        return -1;
    }
    buf = rehash(buf);
    if (!buf) {
        return -1;
    }
    free(buf);
    return 0;
}

int reassign_new_name(void) {
    char *buf = make_buf();

    if (!buf) {
        return -1;
    }
    char *fresh = rehash(buf);
    if (!fresh) {
        free(buf); /* rehash returned before its free(old), so buf is ours */
        return -1;
    }
    free(fresh);
    return 0;
}
