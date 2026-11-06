/*
 * Rule: FIO46-C
 * Source: testcases
 * Status: FAIL - CLOSE is close in a build, the other arm being Windows
 * Settings: posix_version=2008
 */
#include <unistd.h>

#ifdef _WIN32
#define CLOSE _close
#else
#define CLOSE close
#endif

void f(int fd) {
    CLOSE(fd);
    CLOSE(fd);
}
