/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * `returns_allocation` was decided per body from the allocator's spelling,
 * so a wrapper of a wrapper was dark: hostap's `scard = os_zalloc(n); ...
 * return scard;` names no allocator, and no caller of scard_init() ever
 * tracked its result. The flag now closes through the callees whose
 * results reach a return (`returned_callees`, task 1227): os_zalloc ->
 * scard_init -> the caller, whose dropped result is a leak.
 */
#include <stdlib.h>

static void *os_zalloc(size_t size) {
    return calloc(1, size);
}

struct scard_data {
    int ctx;
};

static struct scard_data *scard_init(int ctx) {
    struct scard_data *scard;
    scard = os_zalloc(sizeof(*scard));
    if (scard == NULL) {
        return NULL;
    }
    scard->ctx = ctx;
    return scard;
}

int use_card(int ctx) {
    struct scard_data *scard = scard_init(ctx);
    if (scard == NULL) {
        return -1;
    }
    return scard->ctx;
}
