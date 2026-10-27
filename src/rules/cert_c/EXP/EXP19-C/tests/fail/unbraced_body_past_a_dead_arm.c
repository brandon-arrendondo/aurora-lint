/*
 * Rule: EXP19-C
 * Source: custom
 * Status: FAIL - Should trigger EXP19-C violation
 * Description: An #if 0 arm is never compiled, so it is no configuration.
 * A body that comes through a chain whose first arm is #if 0 is the first
 * statement of a live arm, and is reported there.
 * Expect: count=2
 */

void old_path(void);
void new_path(void);

void dead_first_arm(int x)
{
    if (x)
#if 0
        old_path();
#else
        new_path(); /* Expect: here */
#endif
}

void dead_arm_then_the_body(int x)
{
    if (x)
#if 0
        { old_path(); }
#endif
        new_path(); /* Expect: here */
}
