/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation (aurora_lint 1437).
 * `relay` dereferences `out` (a genuine read) AND forwards it to `writer`,
 * whose own write status this translation unit can never resolve (it
 * forwards again to an undefined `external_writer`). `credit_modifies_params`
 * deliberately withholds a parameter from `modifies_params` while its
 * forwarding obligation is still unresolved -- an open question, not a
 * proven negative -- so `build_read_only_deref_fns` must not treat that
 * omission as proof `relay`'s param 0 is read-only. Companion to
 * fail/testcases_crossfile_readonly_deref.c, which has no forwarding at all
 * and must stay flagged.
 */

static void writer(int *out) {
    external_writer(out);
}

int relay(int *out) {
    int v = *out;
    writer(out);
    return v;
}

void f(void) {
    int data;
    relay(&data);
}
