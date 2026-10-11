/*
 * Rule: MEM04-C
 * Source: testcases
 * Status: PASS - Non-zero allocations with explicit sizes
 */

#include <stdlib.h>

/* Literal size — clearly non-zero */
void literal_alloc(void) {
    int *p = (int *)malloc(40);
    if (p) free(p);
}

/* sizeof expression — always non-zero for complete types */
void sizeof_alloc(void) {
    int *p = (int *)malloc(sizeof(int));
    if (p) free(p);
}

/* calloc with sizeof */
void calloc_sizeof(void) {
    int *p = (int *)calloc(10, sizeof(int));
    if (p) free(p);
}

/* calloc with explicit count and size */
void explicit_calloc(void) {
    int *p = (int *)calloc(10, 4);
    if (p) free(p);
}
