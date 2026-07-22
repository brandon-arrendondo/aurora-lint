/*
 * Rule: ARR30-C
 * Source: task 206 (alias-bound CWE-129 subscript FP)
 * Status: FAIL - Should trigger ARR30-C violation
 * Reason: mirrors Juliet CWE121_..._CWE129_large_32's bad(): same
 * write-through-one-pointer, read-through-another-aliased-pointer shape as
 * the companion pass/aliased_ptr_writeback_const.c fixture, but the traced
 * value is 10 -- out of bounds for a 10-element buffer, and (unlike the
 * goodB2G variant) not protected by a range guard. Must remain flagged: the
 * new alias-resolution proof is additive-only and must never suppress a
 * genuine out-of-bounds access.
 */

void bad(void)
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
            if (data >= 0)
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
