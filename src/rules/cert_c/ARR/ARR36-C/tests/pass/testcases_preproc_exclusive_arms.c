/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to
 *       the same array
 * Status: PASS
 * Reason: The two arms of an #ifdef/#else cannot both exist, so a base
 *         recorded in one is not a base in the other. aurora-lint does not
 *         preprocess and tree-sitter parses BOTH arms, so a name declared once
 *         per arm gets a single timeline interleaving two lifetimes that never
 *         occur together -- and a positional lookup, reading backwards, hands
 *         the #else arm's 'pos' the array the #ifdef arm's 'pos' held.
 *
 *         Distilled from hostap src/drivers/driver_ndis.c, where
 *         wpa_driver_ndis_get_names declares 'pos' in each arm and the
 *         chained 'pos2 = pos = names' records nothing, so nothing in the
 *         #else arm displaced the #ifdef arm's base.
 *
 *         The counterpart is fail/testcases_preproc_base_before_fork.c: a base
 *         recorded ABOVE the #if coexists with both arms and still reports.
 */

#include <stddef.h>

extern char raw_names[];

size_t adapter_names(void)
{
#ifdef CONFIG_USE_UNICODE
    char wide[64];
    char *pos;

    pos = wide;
    return (size_t) (pos - wide);
#else
    char *names, *pos, *pos2;

    names = (char *) raw_names;
    pos2 = pos = names;
    (void) pos2;
    return (size_t) (pos - names);
#endif
}

int main(void)
{
    return (int) adapter_names();
}
