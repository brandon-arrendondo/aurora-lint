/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: PASS - CLOSE is close only until the #undef; at the calls it is another function
 * Settings: posix_version=2008
 */
#include <unistd.h>

int other(int fd);

#define CLOSE close
#undef CLOSE
#define CLOSE other

void f(int fd) {
    CLOSE(fd);
    CLOSE(fd);
}
