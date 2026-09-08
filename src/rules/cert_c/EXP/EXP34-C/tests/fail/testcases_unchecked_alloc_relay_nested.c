/*
 * Rule: EXP34-C
 * Source: testcases (hostap EXP34-C parameter cohort)
 * Status: FAIL - the allocation is NOT checked before being relayed, so
 *         `sink` can dereference NULL. This is the companion to
 *         pass/testcases_nested_checked_alloc_relay.c: it pins that crediting
 *         a checked allocation does not also credit an unchecked one.
 */

#include <stdio.h>
#include <stdlib.h>

void sink(int *ptr) {
    *ptr = 100;
    printf("Value: %d\n", *ptr);
}

int relay(int flag) {
    int *data = NULL;

    if (flag) {
        data = malloc(sizeof(int));
        sink(data);
        free(data);
    }

    return 0;
}
