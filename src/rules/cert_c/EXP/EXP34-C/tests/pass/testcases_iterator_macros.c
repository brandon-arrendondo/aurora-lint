/*
 * Rule: EXP34-C
 * Source: testcases (macro-expansion Phase 1, task 180)
 * Status: PASS - Should NOT trigger EXP34-C
 *
 * An iterator macro's loop variable is guaranteed non-null inside the body by
 * the macro's expanded loop condition, which the parser cannot see. A find
 * macro's output is dereferenced only under an explicit null guard.
 */

struct node { struct node *next, *prev; int data; };
struct item { int id; char *name; };
void use_int(int);
void use_str(const char *);

/* el is non-null inside the DL_FOREACH body (loop condition guards it) */
void compliant_foreach_deref(struct node *head) {
    struct node *el, *tmp;
    DL_FOREACH_SAFE(head, el, tmp) {
        use_int(el->data);
    }
}

/* out dereferenced only inside its if(out) guard */
void compliant_find_guarded(struct item *items, int id) {
    struct item *out;
    HASH_FIND_INT(items, &id, out);
    if (out) {
        use_str(out->name);
    }
}
