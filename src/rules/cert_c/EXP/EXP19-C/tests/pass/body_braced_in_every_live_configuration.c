/*
 * Rule: EXP19-C
 * Source: custom
 * Status: PASS - Should NOT trigger EXP19-C violation
 * Description: An #if 0 arm is never compiled, so an unbraced statement in
 * it is no configuration's body. A body braced in every live arm, or after
 * a chain whose only unbraced arm is dead, gives no finding.
 */

void old_path(void);
void new_path(void);

void dead_arm_unbraced(int x)
{
    if (x)
#if 0
        old_path();
#else
        { new_path(); }
#endif
    old_path();
}

void dead_arm_then_a_braced_body(int x)
{
    if (x)
#if 0
        old_path();
#endif
        { new_path(); }
}

int braced_split_inside_an_else(int a, int b)
{
#ifdef FEATURE_A
    if (a && b)
#else
#ifdef FEATURE_B
    if (b)
#else
    if (a)
#endif
#endif
    {
        return 1;
    }
    return 0;
}
