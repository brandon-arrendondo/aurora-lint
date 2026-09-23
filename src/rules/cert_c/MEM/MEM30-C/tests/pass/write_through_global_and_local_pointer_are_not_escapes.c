/*
 * Rule: MEM30-C
 * Source: real-world (sel4 drivers/timer/*-mct.c, arch/arm/machine/gic_v3.c;
 *         valkey cluster_legacy.c, evict.c, acl.c, fuzzer_client.c -- 35
 *         adjudicated FPs in run 267)
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Reason: "Stack pointer escape: local array/VLA assigned to global" fired
 *         with no local, no array and no VLA. Shape A: the statement writes
 *         THROUGH a global pointer (`mct->global.tcon = ...`, `myself->flags
 *         |= ...`, `map[i]->waker = ...`); the global is only the base of the
 *         lvalue and never changes what it holds. Shape B: a global is
 *         assigned from a local POINTER whose pointee is heap, the global's
 *         own previous value, or a pthread argument -- "not a global and not
 *         a parameter" is not "automatic storage". Both are now read from
 *         the declarators (ADR-0006): the target must be the global name
 *         itself, and the value must be a local array/VLA or `&` of a local
 *         or parameter object.
 */

#include <stdlib.h>

#define GTCON_EN 0x100

typedef struct { unsigned tcon; unsigned cnt; } mct_global_t;
typedef struct { mct_global_t global; int x; } mct_t;
struct node { int flags; long epoch; };

mct_t *mct = (mct_t *)0x10000000;      /* file-scope MMIO pointer */
struct node *myself;                   /* global pointer to a heap object */
struct node *rdist_map[4];
struct node *EvictionPoolLRU;
struct node *Users;
static __thread struct node *thread_error_list;
char *gbuf;

void shape_a_writes_through_global(int core_id, unsigned val)
{
    mct->global.tcon = GTCON_EN;
    mct->global.cnt = val;
    myself->flags |= 2;
    myself->epoch = 7;
    rdist_map[core_id]->flags = 1;
}

void shape_b_local_pointer_to_non_automatic(void *arg)
{
    struct node *ep = malloc(sizeof(*ep) * 16);
    struct node *old_users = Users;
    struct node *data = (struct node *)arg;

    EvictionPoolLRU = ep;              /* heap */
    Users = old_users;                 /* the previous heap object */
    thread_error_list = data;          /* the pthread argument */
}

void static_local_is_not_automatic(void)
{
    static char sbuf[16];
    gbuf = sbuf;
}

void element_of_heap_is_not_automatic(void)
{
    char *heap = malloc(32);
    gbuf = &heap[4];
}
