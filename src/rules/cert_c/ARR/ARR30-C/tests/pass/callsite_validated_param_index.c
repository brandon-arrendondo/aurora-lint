/*
 * Rule: ARR30-C
 * Status: PASS - Should NOT trigger ARR30-C violation
 */

/*
 * Reason: the deliberate validate-then-act split (task 911). `invoke_inject`
 * indexes `lr` with its own `index` parameter and re-checks nothing, which
 * read on its own looks like an unvalidated function-parameter index. Its
 * only caller range-checks `index` before passing it, which is the whole
 * point of seL4's decodeX()/invokeX() convention and of curl's
 * Curl_bufq_peek_at()/chunk_peek_at() pair.
 */

#define NUM_LIST_REGS 4

int invoke_inject(unsigned long *lr, unsigned long index, unsigned long virq)
{
    lr[index] = virq;
    return 0;
}

int decode_inject(unsigned long *lr, unsigned long index, unsigned long virq)
{
    if (index >= NUM_LIST_REGS) {
        return -1;
    }
    return invoke_inject(lr, index, virq);
}
