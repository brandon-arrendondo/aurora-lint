/*
 * Rule: MEM00-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM00-C violation (task 318)
 * Description: A "release_X"-named function freeing every resource
 * passed to it is a dedicated destructor helper, not a
 * same-abstraction-level violation -- see testcases_helper_frees_param.c.
 */

#include <stdlib.h>

void release_resources(char *buf, int *ids, double *vals) {
    free(buf);
    free(ids);
    free(vals);
}
