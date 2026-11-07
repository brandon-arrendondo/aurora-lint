/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: A function-like macro named close is not the library call.
 * This one drops its argument, so the descriptor is still held.
 */

extern int epoll_create(int size);
extern int do_nothing(void);

#define close(x) do_nothing()

int dropped(void)
{
    int fds[2];
    fds[0] = epoll_create(1024); /* Expect: here */
    close(fds[0]);
    return 0; /* Expect: here */
}
