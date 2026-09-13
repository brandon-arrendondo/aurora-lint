/*
 * Rule: INT16-C
 * Source: task-follow-up (array-index sweep-in)
 * Status: PASS - should NOT trigger INT16-C violation
 * Description: when the flagged operand is a subscript expression
 * (`arr[idx]`), the thing actually bitwise-operated on is the ARRAY
 * ELEMENT, never the index. The checker's operand-resolution fallback
 * previously walked the subscript's direct children and caught the
 * loop/array index identifier instead -- here the element type (unsigned)
 * is what matters, and a signed index must not trigger a finding.
 */
void mask_unsigned_element(unsigned int *arr, int idx) {
    unsigned int masked = arr[idx] & 0xFFu;
    (void)masked;
}
