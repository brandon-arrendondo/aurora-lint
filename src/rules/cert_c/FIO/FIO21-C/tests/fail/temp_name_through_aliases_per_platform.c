/*
 * Rule: FIO21-C
 * Source: regression
 * Status: FAIL - Should trigger FIO21-C violation
 *
 * The call is spelled through an object-like alias defined one way per
 * platform, as Juliet's CWE-377 cases spell it. One live definition is
 * tmpnam, so the call reaches tmpnam in that build.
 */

#include <stdio.h>
#include <fcntl.h>

#ifdef _WIN32
#define TMPNAM _wtmpnam
#define OPEN _wopen
#else
#define TMPNAM tmpnam
#define OPEN open
#endif

void make_scratch(void) {
    char *filename = TMPNAM(NULL);
    int fd;
    if (filename == NULL) {
        return;
    }
    fd = OPEN(filename, O_RDWR | O_CREAT, 0600);
    (void)fd;
}
