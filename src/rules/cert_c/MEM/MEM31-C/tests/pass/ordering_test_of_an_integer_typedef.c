/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should not trigger MEM31-C violation
 * Description: An ordering test stays a failure test on an operand that
 * resolves to an integer, a typedef of int here, or whose type does not
 * resolve, a typedef this file cannot see.
 */

#include <unistd.h>

typedef int fd_t;
int epoll_create(int size);
int use(int fd);

int through_a_typedef(void)
{
    fd_t fd = epoll_create(1);
    if (fd < 0) {
        return -1;
    }
    use(fd);
    close(fd);
    return 0;
}

int through_a_typedef_only_a_header_declares(void)
{
    unseen_t fd = epoll_create(1);
    if (fd < 0) {
        return -1;
    }
    use(fd);
    close(fd);
    return 0;
}
