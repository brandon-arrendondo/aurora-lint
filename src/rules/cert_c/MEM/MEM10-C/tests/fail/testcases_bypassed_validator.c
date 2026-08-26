/*
 * Rule: MEM10-C
 * Source: task 595
 * Status: FAIL - The file already defines a dedicated pointer-validation
 * function ("valid"), so an ad hoc NULL check elsewhere in the same file is
 * a genuine inconsistency: a shared validator was available but bypassed.
 */

int valid(void *ptr) {
    return ptr != NULL;
}

void incr(int *intptr) {
    if (intptr == NULL) {
        return;
    }
    (*intptr)++;
}
