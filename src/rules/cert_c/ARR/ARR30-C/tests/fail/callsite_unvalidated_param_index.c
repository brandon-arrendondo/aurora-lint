/*
 * Rule: ARR30-C
 * Status: FAIL - Should trigger ARR30-C violation
 */

/*
 * Reason: the counterpart to pass/callsite_validated_param_index.c. The
 * callee still indexes with a bare parameter, and its one call site passes a
 * value straight from the caller's own unchecked parameter, so nothing in
 * this translation unit bounds `index` (task 911).
 */

int invoke_inject(unsigned long *lr, unsigned long index, unsigned long virq)
{
    lr[index] = virq;
    return 0;
}

int decode_inject(unsigned long *lr, unsigned long index, unsigned long virq)
{
    return invoke_inject(lr, index, virq);
}
