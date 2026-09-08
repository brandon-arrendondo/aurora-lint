/**
 * Rule: EXP34-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP34-C violation. The dominating-dereference
 * exemption (task 1058) must not fire when nothing dereferenced the pointer
 * first: there the `if (p && ...)` is a real guard, the pointer really can be
 * null on the other edge, and the later unguarded dereference is a genuine
 * finding. Keying that exemption on the NotNull lattice value instead of on an
 * actual dereference would silence exactly these.
 */
struct sm { int id; };
struct sta { struct sm *eapol_sm; void *hs20_ie; };

void use(int v);
int helper(struct sta *s);

/* no prior dereference -- the check is a real guard */
void guarded_then_unguarded(struct sta *sta) {
    if (sta && helper(sta) < 0)
        return;
    if (sta->hs20_ie)
        use(1);
}

/* the only prior dereference is inside a preceding if BODY, so it may not run */
void deref_only_in_branch(struct sta *sta, int cond) {
    if (cond)
        use(sta->eapol_sm->id);
    if (sta && helper(sta) < 0)
        return;
    if (sta->hs20_ie)
        use(2);
}

/* the exact FALSE edge of a lone test still refines -- `if (p) {}` leaves p
   definitely null on the fallthrough, and the compound-operator change of
   task 1067 must not have disabled that */
void lone_test_then_deref(struct sta *sta) {
    if (sta)
        use(5);
    use(sta->eapol_sm->id);
}
