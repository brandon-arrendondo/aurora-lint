/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM30-C violation
 *
 * The bug the old list_uaf fixture meant to show: the node is freed and
 * THEN read. Companion to
 * pass/list_traversal_advances_before_freeing.c, which is the
 * same loop with the free after the last read. (The tighter `free(current);
 * current = current->next;` is a recall gap of its own: the assignment
 * clears `current` before its right-hand side is read -- filed separately.)
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
        node_t *next = current->next;
        free(current);
        printf("Data: %d\n", current->data); /* reads the freed node */
        current = next;
    }

    return 0;
}
