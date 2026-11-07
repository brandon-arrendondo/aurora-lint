/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: A macro named close is not the library call. What it expands
 * to decides what happens, and a callee nothing is known about releases
 * nothing.
 */

extern int epoll_create(int size);
extern int my_close(int fd);

#define close my_close

int renamed(void)
{
    int fds[2];
    fds[0] = epoll_create(1024); /* Expect: here */
    close(fds[0]);
    return 0; /* Expect: here */
}
