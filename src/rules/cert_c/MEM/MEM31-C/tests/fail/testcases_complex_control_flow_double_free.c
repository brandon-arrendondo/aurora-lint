/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: `free(buffer1)` at line 31 followed by `goto cleanup`, whose
 * block frees `buffer1` again at line 44 -- and the same for `buffer2` via
 * lines 36 and 45. The expected findings are those two double frees.
 *
 * For a long time this file passed for the wrong reason: the double frees
 * were never detected (the label's `if (x) free(x);` bodies are braceless,
 * and the walk skipped a braceless `if` consequence entirely), and the file
 * stayed green only because the gotos tripped two "may not be freed due to
 * goto" leak findings that are themselves wrong -- the cleanup block frees
 * both buffers. Do not read those leak findings as this fixture's defect;
 * when the goto-label prescan learns to see the label's later sibling
 * statements they go away, and the double frees are what must remain.
 */

#include <stdio.h>
#include <stdlib.h>

int process_with_goto(int condition) {
    int *buffer1 = malloc(100 * sizeof(int));
    int *buffer2 = malloc(200 * sizeof(int));

    if (!buffer1 || !buffer2) {
        goto cleanup;
    }

    if (condition == 1) {
        free(buffer1);
        goto cleanup;  // Will free buffer1 again
    }

    if (condition == 2) {
        free(buffer2);
        goto cleanup;  // Will free buffer2 again
    }

    // Normal processing
    printf("Processing data\n");

cleanup:
    if (buffer1) free(buffer1);  // Potential double free
    if (buffer2) free(buffer2);  // Potential double free

    return 0;
}

int main() {
    process_with_goto(0);  // Normal case
    process_with_goto(1);  // Double free buffer1
    process_with_goto(2);  // Double free buffer2

    return 0;
}