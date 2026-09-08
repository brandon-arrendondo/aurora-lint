/**
 * Rule: EXP34-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP34-C violation. Neither edge of a
 * compound condition licenses a per-operand conclusion in the direction the
 * operator makes disjunctive:
 *
 *   `A && B` FALSE is `!A || !B` -- says nothing about either conjunct.
 *   `A || B` TRUE  is  `A ||  B` -- says nothing about either disjunct.
 *
 * parse_all_null_conditions descended both operators and returned the
 * sub-conditions verbatim, so apply_edge_refinement applied each operand's own
 * state on those edges: `!(sta && f(...))` was read as `!sta`, and
 * `(!p || !q)` marked BOTH p and q definitely null. Those edges now carry no
 * per-variable conclusion (task 1067).
 */
struct sm { int id; };
struct sta { struct sm *eapol_sm; void *hs20_ie; };

void use(int v);

/* `!p || !q` true edge must not conclude either is null */
void or_true_edge(struct sta *p, struct sta *q) {
    if (!p || !q) {
        use(p ? 1 : 0);
        return;
    }
    use(p->eapol_sm->id);
}

/* the exact edges still refine: `A || B` FALSE means both are false */
void or_false_edge_is_exact(struct sta *p, struct sta *q) {
    if (!p || !q)
        return;
    use(p->eapol_sm->id);
    use(q->eapol_sm->id);
}

/* and a lone guard is untouched by the compound-operator change */
void plain_guard(struct sta *p) {
    if (!p)
        return;
    use(p->eapol_sm->id);
}
