/*
 * Rule: ARR30-C
 * Source: task 206 (alias-bound CWE-129 subscript FP)
 * Status: PASS - Should NOT trigger ARR30-C violation
 * Reason: mirrors Juliet CWE121_..._CWE129_large_32's goodB2G(): the traced
 * value through the pointer alias is 10 (out of bounds for a 10-element
 * buffer), but the access is properly guarded by a full range check
 * (`data >= 0 && data < 10`). Locks in the required ordering: the new
 * alias-resolution constant proof must be additive-only (a SAFE proof, never
 * a violation short-circuit) so a resolved-but-out-of-range value still
 * falls through to the existing bounds-check-guard logic instead of
 * becoming a new false positive.
 */

static void goodB2G(void)
{
    int data;
    int *dataPtr1 = &data;
    int *dataPtr2 = &data;
    data = -1;
    {
        int data = *dataPtr1;
        data = 10;
        *dataPtr1 = data;
    }
    {
        int data = *dataPtr2;
        {
            int i;
            int buffer[10] = { 0 };
            if (data >= 0 && data < 10)
            {
                buffer[data] = 1;
                for (i = 0; i < 10; i++)
                {
                    buffer[i] = buffer[i];
                }
            }
        }
    }
}
