/*
 * Rule: INT16-C
 * Source: task-follow-up (array-index sweep-in)
 * Status: FAIL - should trigger INT16-C violation
 * Description: the twin of tests/pass/
 * testcases_array_index_signedness_irrelevant.c -- here the array ELEMENT
 * itself is signed (`int *arr`), so the bitwise operation genuinely is on a
 * signed integer object. The index is unsigned, isolating that the
 * violation tracks the element's type, not the index's.
 */
void mask_signed_element(int *arr, unsigned int idx) {
    int masked = arr[idx] & 0xFF;
    (void)masked;
}
