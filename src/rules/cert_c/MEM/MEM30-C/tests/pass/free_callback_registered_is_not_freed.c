/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * `listSetFreeMethod(list, aofListFree)` REGISTERS a free callback; the
 * identifier is a function designator, not an object, so nothing is released
 * through it. The last-argument heuristic read the callback itself as the
 * freed thing, and registering the same one on two lists in a function came
 * back as "aofListFree freed multiple times" (valkey aof.c, sentinel.c,
 * valkey-cli.c).
 */
#include <stdlib.h>

struct list {
    void (*free_method)(void *);
};

static void aofListFree(void *ptr) {
    free(ptr);
}

void listSetFreeMethod(struct list *l, void (*m)(void *));

void aofManifestCreate(struct list *incr, struct list *history) {
    listSetFreeMethod(incr, aofListFree);
    listSetFreeMethod(history, aofListFree);
}
