/*
 * Rule: EXP19-C
 * Source: custom
 * Status: PASS - Should NOT trigger EXP19-C violation
 * Description: An if whose condition is split across #if arms, body
 * included, inside a block the file proves is never compiled (#if 0).
 * The if exists in no configuration, so the live statement after the
 * dead block's #endif is no if's body.
 */

int split_if_in_a_dead_block(int a, int b)
{
#if 0
#ifdef FAST_PATH
    if (a)
#else
    if (b)
#endif
        b--;
#endif
    b++;
    return b;
}

int split_if_in_a_dead_block_inside_a_feature_arm(int a, int b)
{
#ifdef FEATURE
#if 0
#ifdef FAST_PATH
    if (a)
#else
    if (b)
#endif
        b--;
#endif
    b++;
#endif
    return b;
}
