/**
 * Rule: EXP34-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP34-C violation. Each function dereferences
 * `sta` and then tests it for NULL, with nothing in between that proves it
 * non-null. The later test is the code's own statement that `sta` can be
 * NULL, so the first dereference is the site (CERT's third noncompliant
 * example has this shape). The later dereferences depend on the same missing
 * check: the default policy folds them into the first site, and the strict
 * policy reports every line.
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
