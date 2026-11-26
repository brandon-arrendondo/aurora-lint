/*
 * Rule: MEM31-C
 * Source: synthetic
 * Status: PASS - Every name in a chained assignment holds the block
 *
 * `first = last = key` stores `key` into `last` and then `last` into
 * `first`, so both hold the block `key` holds. A list built with a head
 * and a tail that way and returned through the head is the caller's, and
 * a block freed through `first` is freed under every name.
 */
#include <stdlib.h>

struct node {
    struct node *next;
    int value;
};

int more(void);

struct node *list_returned_through_its_head(void)
{
    struct node *first = NULL, *last = NULL, *key;

    while (more()) {
        key = malloc(sizeof(*key));
        if (!key)
            break;
        key->next = NULL;
        if (!last) {
            first = last = key;
        } else {
            last->next = key;
            last = key;
        }
    }
    return first;
}

void block_freed_through_the_head(void)
{
    char *first, *last, *key;

    key = malloc(16);
    if (!key)
        return;
    first = last = (char *)key;
    last[0] = '\0';
    free(first);
}
