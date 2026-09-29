/*
 * Rule: MEM30-C
 * Source: real-world (valkey vset.c pvPush: `return pvInsertAt(pv, elem,
 *         pvLen(pv));`, pvInsertAt reallocating pv)
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: C evaluates a call's arguments before the call, so reading
 * the old pointer in an argument of the call that reallocates it happens
 * while the block is still live.
 */
#include <stdlib.h>

struct vec {
    size_t len;
    void *items[1];
};

size_t vec_len(struct vec *v)
{
    return v ? v->len : 0;
}

struct vec *vec_insert_at(struct vec *v, void *elem, size_t at)
{
    (void)elem;
    return realloc(v, sizeof(*v) + (at + 1) * sizeof(void *));
}

struct vec *vec_push(struct vec *v, void *elem)
{
    return vec_insert_at(v, elem, vec_len(v));
}
