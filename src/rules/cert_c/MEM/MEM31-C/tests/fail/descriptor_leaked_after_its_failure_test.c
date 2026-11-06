/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: The descriptor's own failure test returns with nothing
 * acquired, but a later error return frees the state and drops the
 * descriptor that was acquired. Only that later return leaks.
 * Expect: count=1
 */

#include <stdlib.h>

extern int epoll_create(int size);
int backend_ready(void);

struct state {
    int epfd;
};

struct loop {
    void *apidata;
};

int create_then_fail(struct loop *loop)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state) return -1;
    state->epfd = epoll_create(1024);
    if (state->epfd == -1) {
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
