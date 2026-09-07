/*
 * Rule: INT31-C
 * Source: custom
 * Status: DETECTED. Was expected_fail until the provenance gate learned to
 * read a parameter's provenance off its callers rather than treating every
 * parameter as bounded local state. No caller of this function is visible in
 * the scan set, so its parameters carry unbounded input and the arithmetic is
 * reported.
 */

unsigned char to_byte(float ratio) {
    return (unsigned char)(ratio * 255.0f);
}
