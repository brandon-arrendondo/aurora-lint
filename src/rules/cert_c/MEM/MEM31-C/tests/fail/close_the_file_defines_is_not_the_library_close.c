/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: This file's own close releases nothing, so a call to it leaves
 * the descriptor held.
 */

extern int epoll_create(int size);

static int close(int fd)
{
    return fd;
}

int closed_by_a_function_that_does_not(void)
{
    int fds[2];
    fds[0] = epoll_create(1024); /* Expect: here */
    close(fds[0]);
    return 0; /* Expect: here */
}
