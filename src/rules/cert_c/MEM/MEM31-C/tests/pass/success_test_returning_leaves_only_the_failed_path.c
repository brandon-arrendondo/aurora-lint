/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should not trigger MEM31-C violation
 * Description: A success test with no else, whose branch always leaves, means
 * the code after the if runs only when the acquisition failed, so that code
 * has nothing to release. This is read the way an else arm is read.
 */

#include <stdlib.h>

extern int epoll_create(int size);
void cleanup(void);

struct state {
    int epfd;
    char *buf;
};

struct loop {
    void *apidata;
};

int descriptor_not_minus_one(struct loop *loop)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state) return -1;
    state->epfd = epoll_create(1024);
    if (state->epfd != -1) {
        loop->apidata = state;
        return 0;
    }
    free(state);
    return -1;
}

int descriptor_not_negative(struct loop *loop)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state) return -1;
    state->epfd = epoll_create(1024);
    if (state->epfd >= 0) {
        loop->apidata = state;
        return 0;
    }
    free(state);
    return -1;
}

int field_not_null(struct loop *loop)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state) return -1;
    state->buf = malloc(8);
    if (state->buf != NULL) {
        loop->apidata = state;
        return 0;
    }
    free(state);
    return -1;
}

int pointer_not_null(void)
{
    char *p = malloc(8);
    if (p != NULL) {
        free(p);
        return 0;
    }
    cleanup();
    return -1;
}

int pointer_truthy(void)
{
    char *p = malloc(8);
    if (p) {
        free(p);
        return 0;
    }
    cleanup();
    return -1;
}

int branch_leaves_by_goto(void)
{
    char *p = malloc(8);
    if (p != NULL) {
        free(p);
        goto out;
    }
    cleanup();
    return -1;
out:
    return 0;
}
