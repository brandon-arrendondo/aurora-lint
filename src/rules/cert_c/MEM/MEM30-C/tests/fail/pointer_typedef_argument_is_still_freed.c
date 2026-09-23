/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM30-C violation
 *
 * The non-pointer gate above must key on POSITIVE evidence, never on the
 * absence of a `*` in the type's spelling. `client` is a typedef that hides
 * the pointer, so the declared type reads `client` with no `*`; treating that
 * as a non-pointer deleted a real use-after-free (valkey-benchmark.c:556,
 * `zfree(c)` then `listSearchKey(config.clients, c)`).
 */
#include <stdlib.h>

typedef struct _client {
    int fd;
} *client;

void list_search(client c);

void freeClient(client c) {
    free(c);
    list_search(c);
}
