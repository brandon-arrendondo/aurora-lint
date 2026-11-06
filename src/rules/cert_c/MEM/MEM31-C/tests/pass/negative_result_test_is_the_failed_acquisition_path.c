/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: An acquirer that returns an int, such as a descriptor,
 * reports failure as -1 or a negative value. The branch where the result
 * tests as -1, or below 0, is the failed path: nothing was acquired there,
 * so returning from it leaks nothing. The test's success form, with an
 * else for the failed path, reads the same way. The prototype is in view,
 * so the name is not what makes the call an acquisition.
 */

#include <stdlib.h>

extern int epoll_create(int size);

struct state {
    int epfd;
};

struct loop {
    void *apidata;
};

int create_compared_to_minus_one(struct loop *loop)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state) return -1;
    state->epfd = epoll_create(1024);
    if (state->epfd == -1) {
        free(state);
        return -1;
    }
    loop->apidata = state;
    return 0;
}

int create_compared_below_zero(struct loop *loop)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state) return -1;
    state->epfd = epoll_create(1024);
    if (state->epfd < 0) {
        free(state);
        return -1;
    }
    loop->apidata = state;
    return 0;
}

int create_compared_with_the_constant_first(struct loop *loop)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state) return -1;
    state->epfd = epoll_create(1024);
    if (-1 == state->epfd) {
        free(state);
        return -1;
    }
    loop->apidata = state;
    return 0;
}

int create_tested_for_success(struct loop *loop)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state) return -1;
    state->epfd = epoll_create(1024);
    if (state->epfd >= 0) {
        loop->apidata = state;
        return 0;
    } else {
        free(state);
        return -1;
    }
}
