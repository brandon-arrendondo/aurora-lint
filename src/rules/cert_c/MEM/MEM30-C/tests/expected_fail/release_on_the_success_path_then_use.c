/*
 * Rule: MEM30-C
 * Source: real-world (hostap: an interface-removal call frees the interface
 *         on the path that returns 0, and the caller reads it after a 0)
 * Status: EXPECTED FAIL - Known limitation: the use after free is real, and
 * MEM30-C does not report it.
 *
 * `remove_entry` returns -1 early, before it releases anything, and frees
 * `e` on the path that returns 0. The caller goes on only when it returned
 * 0, so the read of `e->name` follows the release. Proving it needs the
 * correlation between the callee's result and its release: the summary
 * records only that the release MAY happen, and an early exit before a
 * release is exactly what keeps it from counting as always made.
 */
#include <stdlib.h>
#include <stdio.h>

struct entry {
    struct entry *next;
    char name[16];
};

int remove_entry(struct entry **head, struct entry *e)
{
    struct entry **pp = head;

    while (*pp && *pp != e)
        pp = &(*pp)->next;
    if (*pp == NULL)
        return -1;
    *pp = e->next;
    free(e);
    return 0;
}

void drop(struct entry **head, struct entry *e)
{
    if (remove_entry(head, e))
        return;
    printf("removed %s\n", e->name);
}
