/**
 * Rule: EXP34-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP34-C violation. An earlier exit-guard
 * whose OTHER conjuncts are facts at the dereference proves the pointer
 * non-null:
 *
 *   if (isIndex && (!pSchema || (pSchema->flags & 1) == 0)) return 1;
 *   ...
 *   if (isIndex) { ... pSchema->... }
 *
 * Falling past the guard means `!(isIndex && (...))`, which alone says nothing
 * about pSchema -- which is why task 1067's sound join leaves it PossiblyNull.
 * Where `isIndex` is known TRUE the negation collapses to `!(!pSchema || ...)`,
 * i.e. pSchema non-null, with no approximation. sqlite's btree.c and hostap's
 * wpa.c both regressed on this when 1067 landed (task 1074).
 */
struct schema { int flags; int idxHash; };
struct ptk { int kck; int kck_len; };

void use(int v);
int hash_first(int *h);

/* the sqlite btree.c shape: flag guard, then flag-guarded block */
int flag_guarded_block(int isIndex, struct schema *pSchema) {
    if (isIndex && (!pSchema || (pSchema->flags & 1) == 0))
        return 1;

    if (isIndex)
        use(hash_first(&pSchema->idxHash));
    return 0;
}

/* the hostap wpa.c shape: the flag is the left operand of the deref's own && */
int flag_in_same_condition(int mic_len, int key_mic, struct ptk *ptk) {
    if (mic_len) {
        if (key_mic && (!ptk || !ptk->kck_len))
            return 1;
        if (key_mic && ptk->kck)
            use(ptk->kck_len);
    }
    return 0;
}

/* two flags, both known true at the site */
int two_flags(int f, int g, struct schema *p) {
    if (f && g && (!p || p->flags == 0))
        return 1;

    if (f && g)
        use(p->flags);
    return 0;
}

/* `p == NULL` spelling, and a goto bail-out rather than a return */
int equality_spelling_and_goto(int f, struct schema *p) {
    if (f && (p == NULL || p->flags == 0))
        goto out;

    if (f)
        use(p->flags);
out:
    return 0;
}
