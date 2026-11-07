/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: `p == NULL || other` holds with p still allocated, and the
 * negation of a conjunction proves nothing about either operand, so the
 * return under each test can leak. A pointer is never below 0, negated or not.
 */

#include <stdlib.h>

extern int epoll_create(int size);

struct state {
    int epfd;
};

struct loop {
    void *apidata;
};

int either_failed_or_another_condition(int other)
{
    char *p = malloc(8);
    if (p == NULL || other) {
        return -1; /* Expect: here */
    }
    free(p);
    return 0;
}

int descriptor_failed_or_another_condition(struct loop *loop, int other)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state) return -1;
    state->epfd = epoll_create(1024);
    if (state->epfd < 0 || other) {
        free(state);
        return -1; /* Expect: here */
    }
    loop->apidata = state;
    return 0;
}

int negated_conjunction_of_a_failure_test(int other)
{
    char *p = malloc(8); /* Expect: here */
    if (!(p == NULL && other)) {
        free(p);
        return 0;
    }
    return -1; /* Expect: here */
}

int negated_conjunction_of_a_success_test(int other)
{
    char *p = malloc(8);
    if (!(p != NULL && other)) {
        return -1; /* Expect: here */
    }
    free(p);
    return 0;
}

int negated_ordering_of_a_pointer(void)
{
    char *p = malloc(8);
    if (!(p >= 0)) {
        return -1; /* Expect: here */
    }
    free(p);
    return 0;
}
