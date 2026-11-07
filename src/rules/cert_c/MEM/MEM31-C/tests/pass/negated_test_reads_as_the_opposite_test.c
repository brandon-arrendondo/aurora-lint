/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should not trigger MEM31-C violation
 * Description: `!(x >= 0)` is a failure test and `!(x < 0)` a success test, as
 * `!(p != NULL)` and `!(p == NULL)` are for a pointer, so the failed path has
 * nothing to release.
 */

#include <stdlib.h>

extern int epoll_create(int size);

struct state {
    int epfd;
};

struct loop {
    void *apidata;
};

int negated_success_of_a_descriptor(struct loop *loop)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state) return -1;
    state->epfd = epoll_create(1024);
    if (!(state->epfd >= 0)) {
        free(state);
        return -1;
    }
    loop->apidata = state;
    return 0;
}

int negated_failure_of_a_descriptor(struct loop *loop)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state) return -1;
    state->epfd = epoll_create(1024);
    if (!(state->epfd < 0)) {
        loop->apidata = state;
        return 0;
    }
    free(state);
    return -1;
}

int negated_success_of_a_pointer(void)
{
    char *p = malloc(8);
    if (!(p != NULL)) {
        return -1;
    }
    free(p);
    return 0;
}

int negated_failure_of_a_pointer(void)
{
    char *p = malloc(8);
    if (!(p == NULL)) {
        free(p);
        return 0;
    }
    return -1;
}

int double_negation(void)
{
    char *p = malloc(8);
    if (!!p) {
        free(p);
        return 0;
    }
    return -1;
}
