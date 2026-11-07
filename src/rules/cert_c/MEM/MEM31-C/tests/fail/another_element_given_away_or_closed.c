/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: Releasing or handing over one element says nothing about
 * another, and handing a descriptor to a callee that is not seen to release
 * it is no release, as it is not for a variable.
 */

#include <stdlib.h>

extern int epoll_create(int size);
extern int close(int fd);
void use(int fd);

int another_element_closed(void)
{
    int fds[2];
    fds[0] = epoll_create(1024); /* Expect: here */
    close(fds[1]);
    return 0; /* Expect: here */
}

char *another_element_returned(void)
{
    char *blocks[2];
    blocks[0] = malloc(8); /* Expect: here */
    return blocks[1]; /* Expect: here */
}

int another_element_stored(int *out)
{
    int fds[2];
    fds[0] = epoll_create(1024); /* Expect: here */
    *out = fds[1];
    return 0; /* Expect: here */
}

int element_handed_to_an_unknown_callee(void)
{
    int fds[2];
    fds[0] = epoll_create(1024); /* Expect: here */
    use(fds[0]);
    return 0; /* Expect: here */
}

int local_function_pointer_named_close(void)
{
    int fds[2];
    int (*close)(int) = NULL;
    fds[0] = epoll_create(1024); /* Expect: here */
    close(fds[0]);
    return 0; /* Expect: here */
}
