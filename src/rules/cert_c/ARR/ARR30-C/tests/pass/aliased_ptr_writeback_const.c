/*
 * Rule: ARR30-C
 * Source: task 206 (alias-bound CWE-129 subscript FP)
 * Status: PASS - Should NOT trigger ARR30-C violation
 * Reason: mirrors Juliet CWE121_..._CWE129_large_32's goodG2B(): data is
 * written through one aliased pointer (dataPtr1) in one block, then read
 * back through a different pointer aliasing the same storage (dataPtr2) in
 * a sibling block, and used as an array index. Provably 7 (in bounds for a
 * 10-element buffer), but only provable by tracing through the pointer
 * aliasing and disambiguating three separate `data` bindings (outer scalar,
 * and two block-shadowed locals) by AST scope, not by a whole-function
 * text scan.
 */

static void goodG2B(void)
{
    int data;
    int *dataPtr1 = &data;
    int *dataPtr2 = &data;
    data = -1;
    {
        int data = *dataPtr1;
        data = 7;
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
