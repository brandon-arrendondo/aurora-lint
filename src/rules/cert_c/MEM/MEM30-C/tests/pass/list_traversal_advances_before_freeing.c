/*
 * Rule: MEM30-C
 * Source: testcases (was fail/testcases_list_uaf.c)
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * The textbook way to free a linked list: remember the node, advance the
 * cursor, free the remembered node. `current` is reassigned to the next
 * node BEFORE `to_free` is freed, so the free never touches what `current`
 * holds. This file used to be a fail fixture asserting a use-after-free on
 * `current`: the alias `to_free -> current` recorded at the declaration
 * survived the reassignment of `current`, so freeing `to_free` marked the
 * fresh `current` freed too. An alias to a variable is severed when that
 * variable is given a new value (the real bug this shape can
 * have is in fail/list_traversal_frees_before_advancing.c).
 */

#include <stdlib.h>
#include <stdio.h>

typedef struct node {
    int data;
    struct node *next;
} node_t;

int main() {
    node_t *head = malloc(sizeof(node_t));
    head->data = 1;
    head->next = malloc(sizeof(node_t));
    head->next->data = 2;
    head->next->next = NULL;

    node_t *current = head;
    while (current != NULL) {
        printf("Data: %d\n", current->data);

        node_t *to_free = current;
        current = current->next;
        free(to_free);

        if (current != NULL) {
            printf("Next data: %d\n", current->data);
        }
    }

    return 0;
}
