/*
 * Cross-file returns_allocation test — header-only allocator + constructor
 * (task 1343). Resolved only via #include + -I, never scanned under -d.
 */
#ifndef CONSTRUCTOR_H
#define CONSTRUCTOR_H

#include <stdlib.h>

static inline void *os_zalloc(size_t size) {
    return calloc(1, size);
}

struct thing {
    int value;
};

/* Deliberately not "make_"/"create_"/"..._alloc"-shaped, so a positive
 * result here can only come from the returns_allocation summary closure,
 * never from MEM31-C's name-heuristic fallback. */
static inline struct thing *thing_ctor(void) {
    struct thing *t = os_zalloc(sizeof(*t));
    return t;
}

#endif
