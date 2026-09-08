/**
 * Rule: EXP34-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP34-C violation. A null test on a
 * pointer the code has ALREADY dereferenced is dead-defensive: had it been
 * null, the program faulted at the earlier dereference, so the branch where
 * the test says it is null is unreachable. Refining that edge to
 * DefinitelyNull anyway downgraded the pointer at the join and reported a null
 * dereference much further down -- hostap's ieee802_1x_encapsulate_radius
 * dereferences `sta` in its first statement, tests `if (sta && ...)` 36 lines
 * later, and was reported at a `sta->` 65 lines after that (task 1058).
 */
struct sm { int id; };
struct sta { struct sm *eapol_sm; void *hs20_ie; };

void use(int v);
int helper(struct sta *s);

/* deref, then a redundant `sta &&`, then deref again */
void redundant_and_check(struct sta *sta) {
    struct sm *sm = sta->eapol_sm;

    if (!sm)
        return;
    if (sta && helper(sta) < 0)
        return;
    if (sta->hs20_ie)
        use(1);
}

/* the same with an explicit `!= NULL`, and the later deref nested in #ifdef */
void redundant_ne_check(struct sta *sta) {
    struct sm *sm = sta->eapol_sm;

    if (!sm)
        return;
    if (sta != 0 && helper(sta) < 0)
        return;
#ifdef CONFIG_HS20
    if (sta->hs20_ie)
        use(2);
#endif
}

/* the dominating dereference is in a preceding `if` CONDITION, which runs */
void deref_in_preceding_condition(struct sta *sta) {
    if (sta->eapol_sm == 0)
        return;
    if (sta)
        use(3);
    use(sta->eapol_sm->id);
}
