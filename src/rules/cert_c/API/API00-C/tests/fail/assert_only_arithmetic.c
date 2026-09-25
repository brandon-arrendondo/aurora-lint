/*
 * Rule: API00-C
 * Source: custom (curl-shaped)
 * Status: FAIL - Should trigger API00-C violation
 *
 * The only arithmetic on the parameter is inside an assert. It used to be
 * skipped as "compiled out under NDEBUG", but that is only one configuration.
 * In the debug configuration the argument is compiled and evaluated, and
 * `num + 1` overflows for INT_MAX there like anywhere else (ADR-0010 D5).
 */

void assert(int cond);
void DEBUGASSERT(int cond);

int bump(int num)
{
    DEBUGASSERT(num + 1 > 0);
    assert(num * 2 != 0);
    return 0;
}
