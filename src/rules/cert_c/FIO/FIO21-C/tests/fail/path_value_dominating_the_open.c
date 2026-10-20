/*
 * Rule: FIO21-C
 * Source: regression
 * Status: FAIL - Should trigger FIO21-C violation
 *
 * The write every path to the open runs last decides the path and the
 * flags: an initializer in straight-line code, a flags variable set to
 * include O_CREAT, and a name tmpnam() wrote into a buffer in an if
 * condition that runs on every path to the open.
 */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

void initialized_path(void) {
    const char *p = "/tmp/app.out";
    FILE *fp = fopen(p, "w");
    if (fp != NULL) {
        fclose(fp);
    }
}

void flags_variable(void) {
    int flags = O_WRONLY | O_CREAT;
    int fd = open("/var/tmp/app.lock", flags, 0600);
    if (fd != -1) {
        close(fd);
    }
}

void name_filled_in_a_condition(void) {
    char name[L_tmpnam];
    if (tmpnam(name) == NULL) {
        return;
    }
    int fd = open(name, O_WRONLY | O_CREAT, 0600);
    if (fd != -1) {
        close(fd);
    }
}
