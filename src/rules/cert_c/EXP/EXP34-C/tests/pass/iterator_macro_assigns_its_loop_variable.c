/*
 * Rule: EXP34-C
 * Source: synthetic (the doubly-linked-list iterator shape)
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * The iterator macro assigns `item` itself before it reads `item->node`,
 * so the NULL `item` holds when the loop starts is never dereferenced. Only
 * a parameter the macro writes through WITHOUT first assigning it is a
 * dereference of the argument's value.
 */
#include <stddef.h>

struct node { struct node *next; };
struct item { int v; struct node node; };

#define item_of(n) ((struct item *)((char *)(n) - offsetof(struct item, node)))
#define for_each_item(item, head) \
    for ((item) = item_of((head)->next); &(item)->node != (head); \
         (item) = item_of((item)->node.next))

int sum(struct node *head) {
    struct item *item = NULL;
    int total = 0;
    for_each_item(item, head)
        total += item->v;
    return total;
}
