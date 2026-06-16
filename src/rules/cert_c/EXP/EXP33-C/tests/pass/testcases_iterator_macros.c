/*
 * Rule: EXP33-C
 * Source: testcases (macro-expansion Phase 1, task 180)
 * Status: PASS - Should NOT trigger EXP33-C
 *
 * utlist/uthash/BSD-queue iterator/find/output macros write their
 * iterator/temp/out arguments. sqc has no preprocessor, so these used to be
 * flagged as "used uninitialized". The macro_semantics registry models them.
 */

struct node { struct node *next, *prev; int data; };
struct item { int id; char *name; };
void use_int(int);
void use_str(const char *);

/* utlist DL_FOREACH_SAFE: el (iterator) + tmp (temp) are written by the macro */
void compliant_dl_foreach_safe(struct node *head) {
    struct node *el, *tmp;
    DL_FOREACH_SAFE(head, el, tmp) {
        use_int(el->data);
    }
}

/* utlist LL_FOREACH: el is the iterator */
void compliant_ll_foreach(struct node *head) {
    struct node *el;
    LL_FOREACH(head, el) {
        use_int(el->data);
    }
}

/* uthash HASH_ITER: el (iterator) + tmp (temp) */
void compliant_hash_iter(struct item *items) {
    struct item *el, *tmp;
    HASH_ITER(hh, items, el, tmp) {
        use_str(el->name);
    }
}

/* uthash HASH_FIND_INT: out is written (set to found-or-NULL) */
void compliant_hash_find(struct item *items, int id) {
    struct item *out;
    HASH_FIND_INT(items, &id, out);
    if (out) {
        use_str(out->name);
    }
}

/* uthash HASH_FIND_BYHASHVALUE / HASH_REPLACE family: output is the LAST arg
 * (matched by prefix, not enumeration) */
void compliant_hash_find_byhashvalue(struct item *items, unsigned hv) {
    struct item *out;
    HASH_FIND_BYHASHVALUE(hh, items, "k", 1, hv, out);
    if (out) {
        use_str(out->name);
    }
}
