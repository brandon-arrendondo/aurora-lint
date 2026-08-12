/*
 * Rule: ARR30-C
 * Status: FAIL - Should trigger ARR30-C violation
 */

/*
 * Reason: the macro-named bound resolves, but it's WRONG -- larger than the
 * actual buffer -- so this guard doesn't actually make the access safe.
 * Resolving the macro must still catch an insufficient guard (task 443),
 * not just accept any `idx < MACRO_NAME` unconditionally.
 */

#define TOO_BIG 20

int buf[10];
extern int external_index;

void f(void)
{
    int idx = external_index;
    if (idx < TOO_BIG)
    {
        buf[idx] = 1;
    }
}
