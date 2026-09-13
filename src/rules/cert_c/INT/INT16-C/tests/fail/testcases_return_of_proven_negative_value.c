/*
 * Rule: INT16-C
 * Source: task-follow-up (return-path VRA gate)
 * Status: FAIL - a value proven negative on this path is returned from an
 * unsigned function
 */

unsigned int compute_code(int rc) {
    if (rc < 0) {
        return rc;
    }
    return 0;
}
