/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: nRef is declared volatile, so reading p->nRef is a volatile access
 * (C11 5.1.2.3p2), resolved through the typedef (tag and alias share a
 * name, the usual idiom) to the struct's member.
 */

#include <assert.h>

typedef struct mutex_t mutex_t;
struct mutex_t {
    int id;
    volatile int nRef;
};

void leave(mutex_t *p) {
    assert(p->nRef > 0);  // VIOLATION
}
