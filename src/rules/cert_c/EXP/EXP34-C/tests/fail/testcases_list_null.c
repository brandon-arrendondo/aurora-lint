/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: FAIL - main() passes NULL to print_list() which dereferences head->next.
 *         Detected via intra-file prescan (call-site null state propagation).
 */

#include <stdio.h>
#include <stdlib.h>

typedef struct Node {
    int data;
    struct Node *next;
} Node;

void print_list(Node *head) {
    Node *current = head;

    // No NULL check before accessing node
    while (current->next != NULL) {
        printf("%d ", current->data);
        current = current->next;
    }
}

int main() {
    print_list(NULL);
    return 0;
}