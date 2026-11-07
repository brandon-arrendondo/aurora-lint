/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: A file-scope pointer named close, declared through a typedef,
 * is not the library's close either, and calling it releases nothing.
 */

extern int epoll_create(int size);

typedef int (*closer)(int fd);

static closer close = 0;

int closed_through_a_typedef_pointer(void)
{
    int fds[1];
    fds[0] = epoll_create(1024); /* Expect: here */
    close(fds[0]);
    return 0; /* Expect: here */
}
