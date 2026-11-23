/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: An assignment inside an `if` condition allocates into its
 * left operand exactly as the statement would, and the test of the
 * assignment tests that object. `if ((p = malloc(n)) == NULL) return -1;`
 * returns with nothing acquired, and the later return that drops `p` leaks
 * it, as it does after `p = malloc(n); if (p == NULL) return -1;`. A member
 * target is tracked the same way, descriptors included. Of `A || B`, only
 * the last disjunct's variable is empty in the branch: `p` holds a block
 * there whenever `q` is what failed.
 * Expect: count=12
 */

#include <stdlib.h>

extern int epoll_create(int size);
void use(void *);
int backend_ready(void);

struct state {
    int fd;
    char *buf;
};

struct loop {
    void *apidata;
};

int equals_null(void)
{
    char *p;
    if ((p = malloc(8)) == NULL) /* Expect: here */
        return -1;
    use(p);
    return 0; /* Expect: here */
}

int negated(void)
{
    char *p;
    if (!(p = malloc(8))) /* Expect: here */
        return -1;
    use(p);
    return 0; /* Expect: here */
}

int success_arm_keeps_it(void)
{
    char *p;
    if ((p = malloc(8)) != NULL) { /* Expect: here */
        use(p);
    }
    return 0; /* Expect: here */
}

int member_of_an_owned_block(void)
{
    struct state *s = malloc(sizeof *s);
    if (!s)
        return -1;
    if ((s->buf = malloc(8)) == NULL) { /* Expect: here */
        free(s);
        return -1;
    }
    free(s);
    return 0; /* Expect: here */
}

int descriptor_member(struct loop *loop)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state)
        return -1;
    if ((state->fd = epoll_create(1024)) < 0) {
        free(state);
        return -1;
    }
    if (!backend_ready()) {
        free(state);
        return -1; /* Expect: here */
    }
    loop->apidata = state;
    return 0;
}

int first_of_two_disjuncts(void)
{
    char *p, *q;
    if ((p = malloc(8)) == NULL || (q = malloc(8)) == NULL)
        return -1; /* Expect: here */
    free(p);
    free(q);
    return 0;
}

int ordered_against_minus_one(struct loop *loop)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state)
        return -1;
    if (-1 == (state->fd = epoll_create(1024))) { /* Expect: here */
        free(state);
        return -1;
    }
    free(state);
    return 0; /* Expect: here */
}
