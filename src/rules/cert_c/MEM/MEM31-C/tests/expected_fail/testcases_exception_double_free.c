/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: EXPECTED FAIL - Known limitation: the double free (MEM30-C's
 * concern) is real, and MEM31-C does not report it.
 *
 * `destroy_container` frees `container->buffer` only under a test, so the
 * summary records the field's release as one that MAY happen, and a MAY
 * release cannot back an accusation (see
 * testcases_real_free_before_goto_label.c). This fixture
 * once passed on a misfire instead: handed `&container`, the helper's
 * `container->buffer` was not read as the caller's `container.buffer`, so
 * the block both calls free was reported as never freed.
 */

#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int *buffer;
    size_t size;
} data_container_t;

void destroy_container(data_container_t *container) {
    if (container && container->buffer) {
        free(container->buffer);
        // Error: not setting to NULL allows double free
    }
}

int main() {
    data_container_t container;
    container.buffer = malloc(100 * sizeof(int));
    container.size = 100;

    if (container.buffer) {
        // Simulate exception/error condition
        printf("Processing data...\n");

        // Error path cleanup
        destroy_container(&container);

        // Normal path cleanup - double free
        destroy_container(&container);
    }

    return 0;
}