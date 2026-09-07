/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM30-C violation
 *
 * process_and_free() frees its parameter inside `if (ptr != NULL)`. That is a
 * MAY-free by AST position, but the guard tests only the pointer being freed:
 * the skipped path has nothing to free and so leaves nothing for the caller to
 * use, which is the failure the MUST-free set exists to prevent. It therefore
 * enters unconditional_frees_params, and MEM30-C marks the caller's argument
 * freed at the call (task 988, tools_sqc).
 */

/*
 * Rule: MEM30-C - Do not access freed memory
 * Status: FAIL
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