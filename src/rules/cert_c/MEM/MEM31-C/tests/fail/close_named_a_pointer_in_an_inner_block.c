/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: What close names is read at each call. After the library's
 * close released one descriptor, a block that declares a pointer named close
 * calls that pointer, which releases nothing.
 */

extern int epoll_create(int size);
extern int close(int fd);

int closed_through_an_inner_pointer(void)
{
    int fds[1];
    fds[0] = epoll_create(1024);
    close(fds[0]);
    {
        int (*close)(int fd) = 0;
        fds[0] = epoll_create(1024); /* Expect: here */
        close(fds[0]);
    }
    return 0; /* Expect: here */
}
