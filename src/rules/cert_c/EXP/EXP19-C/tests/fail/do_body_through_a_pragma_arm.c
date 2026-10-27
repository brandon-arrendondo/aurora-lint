/*
 * Rule: EXP19-C
 * Source: custom
 * Status: FAIL - Should trigger EXP19-C violation
 * Description: A do statement whose unbraced body comes after an #if arm
 * of directives is reported as the do statement it is, at its keyword,
 * not as a while statement with an empty body.
 * Expect: count=1
 */

void count_down(int x)
{
    do /* Expect: here */
#ifdef FEATURE_A
#pragma message("counting down")
#endif
        x--;
    while (x);
}
