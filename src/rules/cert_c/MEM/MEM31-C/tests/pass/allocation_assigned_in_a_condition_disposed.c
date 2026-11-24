/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: A block allocated inside an `if` condition and then freed,
 * returned, released at a cleanup label or handed over is disposed of, as
 * it is when the allocation is a statement of its own. The test of the
 * assignment is the allocation's failure test, so the branch it guards
 * returns with nothing acquired. Of `A || B`, the last disjunct's variable
 * was never filled in the branch, so a branch that frees only the first
 * leaks nothing. realloc's result tested in the condition leaves the old
 * block with the caller, who frees it on failure. Of `A && B`, only the last
 * conjunct's variable is empty on the else path, so freeing the first there
 * is enough. A comma condition tests its last operand, and `c ? A : 0` tests
 * what `A` does. `p = q = malloc(n)` binds as the statement does. A block
 * handed over by a later operand of the same condition stays handed over:
 * the condition is read in evaluation order. A comma condition's last
 * operand is read by the success and truthiness tests too, and `c ? 0 : B`
 * tests what `B` does. An assignment inside a call's arguments is not a
 * binding of the condition, as it is not of a statement, so a block handed
 * to the call that way is the call's. `!(A && B)` is the else path of
 * `A && B`.
 */

#include <stdlib.h>

extern int epoll_create(int size);
extern int close(int fd);
void use(void *);

struct state {
    int fd;
};

int freed(void)
{
    char *p;
    if ((p = malloc(8)) == NULL)
        return -1;
    use(p);
    free(p);
    return 0;
}

char *returned(void)
{
    char *p;
    if ((p = malloc(8)) == NULL)
        return NULL;
    use(p);
    return p;
}

int released_at_the_label(void)
{
    char *p;
    int rc = -1;
    if ((p = malloc(8)) == NULL)
        goto out;
    use(p);
    rc = 0;
    free(p);
out:
    return rc;
}

int freed_in_the_success_arm(void)
{
    char *p;
    if ((p = malloc(8)) != NULL) {
        use(p);
        free(p);
    }
    return 0;
}

int truthiness(void)
{
    char *p;
    if ((p = malloc(8))) {
        use(p);
        free(p);
    }
    return 0;
}

int both_disjuncts(void)
{
    char *p, *q;
    if ((p = malloc(8)) == NULL || (q = malloc(8)) == NULL) {
        free(p);
        return -1;
    }
    free(p);
    free(q);
    return 0;
}

int realloc_result(char **out)
{
    char *b = malloc(4), *t;
    if (!b)
        return -1;
    if ((t = realloc(b, 16)) == NULL) {
        free(b);
        return -1;
    }
    b = t;
    *out = b;
    return 0;
}

int descriptor_closed(void)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state)
        return -1;
    if ((state->fd = epoll_create(1024)) < 0) {
        free(state);
        return -1;
    }
    close(state->fd);
    free(state);
    return 0;
}

struct holder {
    char *p;
};

int keep(struct holder *hd, char *p)
{
    hd->p = p;
    return 1;
}

int conjunction_frees_the_first_on_the_else_path(void)
{
    char *p, *q;
    if ((p = malloc(8)) != NULL && (q = malloc(8)) != NULL) {
        free(p);
        free(q);
        return 0;
    }
    free(p);
    return -1;
}

int conjunction_of_truth_tests(void)
{
    char *p, *q;
    if ((p = malloc(8)) && (q = malloc(8))) {
        free(p);
        free(q);
        return 0;
    }
    free(p);
    return -1;
}

int comma_condition(void)
{
    char *p;
    if ((p = malloc(8)), p == NULL)
        return -1;
    free(p);
    return 0;
}

int conditional_with_a_false_arm(int c)
{
    char *p = NULL;
    if (c ? (p = malloc(8)) == NULL : 0)
        return -1;
    free(p);
    return 0;
}

int chained_assignment_binds_as_the_statement_does(void)
{
    char *p, *q;
    if ((p = q = malloc(8)) == NULL)
        return -1;
    free(p);
    return 0;
}

int handed_over_after_it_is_bound(struct holder *hd)
{
    char *p;
    if ((p = malloc(8)) == NULL || !keep(hd, p))
        return -1;
    return 0;
}

int comma_condition_success_arm(void)
{
    char *p;
    if ((p = malloc(8)), p != NULL) {
        use(p);
        free(p);
        return 0;
    }
    return -1;
}

int comma_condition_truthiness(void)
{
    char *p;
    if ((p = malloc(8)), p) {
        use(p);
        free(p);
        return 0;
    }
    return -1;
}

int conditional_with_a_false_consequence(int c)
{
    char *p = NULL;
    if (c ? 0 : (p = malloc(8)) == NULL)
        return -1;
    free(p);
    return 0;
}

int handed_over_in_a_call_argument(struct holder *hd)
{
    char *p;
    if (keep(hd, (p = malloc(8))) == 0)
        return -1;
    return 0;
}

int handed_over_in_a_call_argument_statement(struct holder *hd)
{
    char *p;
    keep(hd, (p = malloc(8)));
    return 0;
}

int negated_conjunction(void)
{
    char *p, *q;
    if (!((p = malloc(8)) && (q = malloc(8)))) {
        free(p);
        return -1;
    }
    free(p);
    free(q);
    return 0;
}
