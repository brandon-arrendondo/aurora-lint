/*
 * Rule: ARR00-C
 * Source: custom
 * Status: PASS - Should NOT trigger ARR00-C violation
 * Description: Known limit, pinned. Each arm of the #if gives `t` one
 * element, so `t[1]` is out of bounds in every build. The parser keeps
 * both arms' entries, and the list it then holds (two entries) is no
 * build's list, so no bound is inferred from it and the read is not
 * checked. Inferring size 2 would not report it either.
 */

int last(void)
{
    int t[] = {
#if defined(WITH_FIRST_ENTRY)
        1,
#else
        2,
#endif
    };
    return t[1];
}
