/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: An element of an int array, an array typedef or an int pointer
 * is an int, as is a member through a typedef of int, so `x < 0` is that
 * descriptor's failure test and returns with nothing acquired. Only the later
 * error return, which frees the state and drops the descriptor, leaks.
 * Expect: count=4
 */

#include <stdlib.h>

extern int epoll_create(int size);
int backend_ready(void);

typedef int fd_t;
typedef int fd_pair_t[2];

struct state {
    int fds[2];
    fd_pair_t pair;
    int *more;
    fd_t fd;
};

struct loop {
    void *apidata;
};

int element_of_an_int_array(struct loop *loop)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state) return -1;
    state->fds[0] = epoll_create(1024);
    if (state->fds[0] < 0) {
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

int element_of_an_array_typedef(struct loop *loop)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state) return -1;
    state->pair[0] = epoll_create(1024);
    if (state->pair[0] < 0) {
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

int element_through_an_int_pointer(struct loop *loop)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state) return -1;
    state->more[0] = epoll_create(1024);
    if (state->more[0] < 0) {
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

int member_through_a_typedef(struct loop *loop)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state) return -1;
    state->fd = epoll_create(1024);
    if (state->fd < 0) {
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
