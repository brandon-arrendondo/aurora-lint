/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should not trigger MEM31-C violation
 * Description: A field or element hands over what it holds the way a variable
 * does, when it is returned or stored through a pointer, and the library's
 * close releases a descriptor held in one.
 */

#include <stdlib.h>

extern int epoll_create(int size);
extern int close(int fd);

struct state {
    int epfd;
    char *buf;
};

int element_closed(void)
{
    int fds[2];
    fds[0] = epoll_create(1024);
    close(fds[0]);
    return 0;
}

int element_closed_twice_is_no_double_free(void)
{
    int fds[2];
    fds[0] = epoll_create(1024);
    close(fds[0]);
    close(fds[0]);
    return 0;
}

int field_closed(void)
{
    struct state *state = malloc(sizeof(struct state));
    if (!state) return -1;
    state->epfd = epoll_create(1024);
    close(state->epfd);
    free(state);
    return 0;
}

int element_returned(void)
{
    int fds[2];
    fds[0] = epoll_create(1024);
    return fds[0];
}

int element_stored_through_a_pointer(int *out)
{
    int fds[2];
    fds[0] = epoll_create(1024);
    *out = fds[0];
    return 0;
}

char *pointer_element_returned(void)
{
    char *blocks[2];
    blocks[0] = malloc(8);
    return blocks[0];
}

char *pointer_element_returned_from_a_conditional(int use_it)
{
    char *blocks[2];
    blocks[0] = malloc(8);
    return use_it ? blocks[0] : NULL;
}

char *field_of_a_local_returned(void)
{
    struct state local;
    local.buf = malloc(8);
    return local.buf;
}

int field_of_a_local_stored_through_a_pointer(char **out)
{
    struct state local;
    local.buf = malloc(8);
    *out = local.buf;
    return 0;
}
