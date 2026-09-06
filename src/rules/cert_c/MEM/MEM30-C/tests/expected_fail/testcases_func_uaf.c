/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: EXPECTED FAIL - Known limitation: process_and_free() frees its parameter
 * inside if (ptr != NULL), so the free is a MAY-free and never enters
 * unconditional_frees_params, which is the set MEM30-C requires before
 * marking a call's argument as freed. That requirement is deliberate --
 * trusting the MAY-free set caused cascading false use-after-free reports
 * -- but a free guarded only by a null check on the pointer being freed is
 * effectively unconditional, since the guarded-out path has nothing to
 * free and nothing to use afterwards. Detected without -d and missed with
 * it. A genuine MEM30-C violation.
 */

/*
 * Rule: MEM30-C - Do not access freed memory
 * Status: EXPECTED FAIL
 * Reason: Function frees memory but caller still accesses it afterwards
 */

#include <stdlib.h>
#include <stdio.h>

void process_and_free(int *ptr) {
    if (ptr != NULL) {
        printf("Processing: %d\n", *ptr);
        free(ptr);
    }
}

int main() {
    int *data = malloc(sizeof(int));
    if (data == NULL) {
        return -1;
    }

    *data = 99;
    process_and_free(data);

    // BUG: Access after function freed it
    printf("Value: %d\n", *data);

    return 0;
}