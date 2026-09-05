/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: FAIL
 * Reason: The walk chases a delimiter the buffer need not contain, so the NUL
 *         terminator does not stop it and the copy runs past both ends. The
 *         terminator-bound suppression must not reach a `!=` against a non-NUL
 *         constant -- only `!=` against NUL bounds a walk.
 */

void copy_to_colon(const char *src, char *dst) {
    while (*src != ':') {
        *dst = *src;
        dst++;
        src++;
    }
    *dst = '\0';
}
