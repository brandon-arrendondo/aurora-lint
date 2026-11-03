/*
 * Rule: EXP33-C
 * Source: custom
 * Status: FAIL - Should trigger EXP33-C violation
 * Description: An #ifdef between the entries of a local array's initializer
 * list, before a variable assigned on one path only. Unrepaired, the #ifdef
 * swallowed the rest of the function body and stranded its closing brace,
 * so the function was never analysed as one and the read of `y` went
 * unreported.
 * Expect: count=1
 */

int pick(int x)
{
    int y;
    int w[] = {
#ifdef WITH_FIRST
        x,
#endif
        1
    };
    if (x > w[0]) {
        y = 1;
    }
    return y; /* Expect: here */
}
