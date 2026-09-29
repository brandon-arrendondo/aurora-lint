/*
 * Rule: MEM31-C
 * Source: real-world (hostap robust_av.c: two dl_list_for_each_safe loops
 *         over the same list, each releasing the element it visits)
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: each iteration macro assigns its cursor as it starts, so the
 * element the second loop releases is not the one the first loop released.
 * A macro whose body assigns an argument rebinds that name.
 */
#include <stdlib.h>
#include <stddef.h>

struct node {
    struct node *next;
    struct node *prev;
};

struct entry {
    struct node list;
    int done;
};

#define node_entry(item, type, member) \
    ((type *) ((char *) (item) - offsetof(type, member)))

#define for_each_entry_safe(item, n, head, type, member) \
    for (item = node_entry((head)->next, type, member), \
         n = node_entry(item->member.next, type, member); \
         &item->member != (head); \
         item = n, n = node_entry(n->member.next, type, member))

void drop_entry(struct entry *e)
{
    e->list.prev->next = e->list.next;
    e->list.next->prev = e->list.prev;
    free(e);
}

void settle(struct node *head)
{
    struct entry *e, *tmp;

    for_each_entry_safe(e, tmp, head, struct entry, list) {
        if (e->done)
            drop_entry(e);
    }

    for_each_entry_safe(e, tmp, head, struct entry, list) {
        drop_entry(e);
    }
}
