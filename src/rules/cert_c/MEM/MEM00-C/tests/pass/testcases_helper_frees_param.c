/*
 * Rule: MEM00-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM00-C violation (task 318)
 * Description: A function whose own name signals it's a dedicated
 * cleanup/destructor helper (cleanup_*/free_*/destroy_*/...) is
 * SUPPOSED to free what's passed in -- that's the entire point of the
 * helper, not a same-abstraction-level violation.
 */

#include <stdlib.h>
#include <string.h>

void cleanup_buffer(char *buf) {
    free(buf);
}

void process(void) {
    char *data = malloc(256);
    if (data == NULL) return;
    strcpy(data, "some data");
    cleanup_buffer(data);
}
