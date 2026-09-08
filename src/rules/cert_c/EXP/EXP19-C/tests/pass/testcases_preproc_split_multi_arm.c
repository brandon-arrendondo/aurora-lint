/*
 * Rule: EXP19-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP19-C violation
 */

/*
 * Rule: EXP19-C - Use braces for the body of an if, for, or while statement
 * Status: PASS
 * Reason: The multi-arm form of the split repaired by
 *         testcases_preproc_split_if_brace.c -- a #if/#elif/#else chain whose
 *         arms each end with an incomplete fragment, all sharing one brace
 *         block placed after the #endif. Every configuration that compiles
 *         picks exactly one arm, and in each the block is braced.
 *
 *         The single-arm repair cannot simply be extended to these: blanking
 *         a chain's directive lines splices every arm into ONE statement
 *         stream (`if (a) if (b) { ... }`), giving the outer `if` a
 *         non-compound consequence and making EXP19-C fire MORE than before.
 *         src/analyze/preproc_split_chain.rs instead keeps the last arm that
 *         ends incomplete and blanks the other arms' dangling fragments.
 *
 *         Distilled from raylib src/platforms/rcore_desktop_sdl.c
 *         (GetMonitorPosition, 16 instances in that file), curl lib/hostip4.c
 *         (the three-way HAVE_GETHOSTBYNAME_R_5/_6/_3 chain, whose arms mix
 *         the bare-`else` and control-header shapes) and sqlite src/analyze.c
 *         (statGet, whose #else arm holds a complete statement).
 */

int check_a(int x);
int check_b(int x);

/* Two arms, both ending in a control header, sharing one brace block. */
int two_arms(int monitor, int count)
{
#if defined(USING_VERSION_SDL3)
    if (check_a(monitor) != 0)
#else
    if ((monitor >= 0) && (monitor < count))
#endif
    {
        return 1;
    }
    return 0;
}

/* Three arms mixing a bare `else` with a control header. */
int mixed_arms(int n)
{
    int h = 0;
    int res = 0;

#ifdef HAVE_R_5
    h = check_a(n);
    if (h) {
        h = 1;
    }
    else
#elif defined(HAVE_R_6)
    h = check_b(n);
    if (!h)
#elif defined(HAVE_R_3)
    res = check_a(n);
    if (!res) {
        h = 1;
    }
    else
#endif
    {
        h = 0;
    }
    return h;
}

/* A #else arm holding a complete statement, between the kept header and the
 * brace block it governs. */
int complete_trailing_arm(int argc)
{
#ifdef ENABLE_STAT4
    int call = check_a(argc);
    if (call == 1)
#else
    check_b(argc);
#endif
    {
        return check_a(0);
    }
    return 0;
}

/* A condition wrapped across two lines: blanking only the last would leave a
 * half-open parenthesis behind. */
int wrapped_condition(int a)
{
#ifdef A
    if (check_a(a)
     && check_b(a + 1))
#else
    if (check_a(a))
#endif
    {
        return 1;
    }
    return 0;
}

/* One of these nested inside another's brace block. */
int nested_chains(int a)
{
#ifdef A
    if (check_a(a) != 0)
#else
    if (a >= 0)
#endif
    {
#ifdef A
        if (check_b(a + 1))
#else
        if (check_b(a + 2) == 0)
#endif
        {
            return 1;
        }
    }
    return 0;
}
