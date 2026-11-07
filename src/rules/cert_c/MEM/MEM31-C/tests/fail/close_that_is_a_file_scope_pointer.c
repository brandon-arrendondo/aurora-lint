/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: A call through a file-scope pointer named close is not the
 * library's close, and releases nothing.
 */

extern int epoll_create(int size);

static int (*close)(int fd);

int closed_through_a_file_scope_pointer(void)
{
    int fds[1];
    fds[0] = epoll_create(1024); /* Expect: here */
    close(fds[0]);
    return 0; /* Expect: here */
}
