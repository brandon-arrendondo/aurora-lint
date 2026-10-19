/*
 * Rule: FIO21-C
 * Source: regression
 * Status: FAIL - Should trigger FIO21-C violation
 *
 * openat() creating a file under P_tmpdir, <stdio.h>'s shared temporary
 * directory, with the flags held in a variable.
 */

#include <stdio.h>
#include <fcntl.h>

int open_state(int dirfd) {
    int flags = O_WRONLY | O_CREAT;
    return openat(dirfd, P_tmpdir "/state", flags, 0600);
}
