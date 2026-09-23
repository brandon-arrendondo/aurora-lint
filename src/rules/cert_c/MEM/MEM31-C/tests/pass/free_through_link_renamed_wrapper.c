/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * valkey renames its allocator family at link time -- `#define zfree
 * valkey_free` -- while the only body the scan ever sees is `void
 * zfree(void *ptr)`. The transitive-frees fixpoint resolved every edge
 * through the alias map first, so `decrRefCount -> zfree(o)` looked up
 * `valkey_free`, found no summary, and credited nothing: every object
 * released through decrRefCount read as a leak once its constructor was
 * recognised. An alias onto a name the scan never saw now falls back to
 * the spelling it did see (task 1227).
 */
#include <stdlib.h>

#define zfree valkey_free

static void zfree_internal(void *ptr) {
    free(ptr);
}

void zfree(void *ptr) {
    if (ptr == NULL) return;
    zfree_internal(ptr);
}

struct robj {
    int refcount;
};

static void decrRefCount(struct robj *o) {
    if (o->refcount == 1) {
        zfree(o);
    } else {
        o->refcount--;
    }
}

static struct robj *createObject(void) {
    struct robj *o = malloc(sizeof(*o));
    if (o) {
        o->refcount = 1;
    }
    return o;
}

int use_object(void) {
    struct robj *o = createObject();
    if (!o) {
        return -1;
    }
    int rc = o->refcount;
    decrRefCount(o);
    return rc;
}
