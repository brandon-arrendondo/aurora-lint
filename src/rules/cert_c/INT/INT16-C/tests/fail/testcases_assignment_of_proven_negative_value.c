/*
 * Rule: INT16-C
 * Source: testcases
 * Status: FAIL - a value proven negative on this path is assigned to an unsigned field
 */

struct result {
    unsigned int code;
};

/* rc is negative everywhere inside the branch, so the assignment really does
   lose the sign. */
void record_failure(struct result *r, int rc) {
    if (rc < 0) {
        r->code = rc;
    }
}
