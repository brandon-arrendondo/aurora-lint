/*
 * Rule: FIO21-C
 * Source: regression
 * Status: PASS - Should NOT trigger FIO21-C violation
 *
 * Calls spelled like the library's that reach something else: a function
 * pointer parameter named tmpnam, a function the file defines as mktemp,
 * and an alias of open to the project's own opener. The callee is resolved
 * by declaration, not by spelling (ADR-0006).
 */

#include <fcntl.h>

int project_open(const char *path, int flags, int mode);

#define OPEN project_open

static char *mktemp(char *tmpl) {
    tmpl[0] = 'x';
    return tmpl;
}

char *name_with(char *(*tmpnam)(char *), char *buf) {
    char *n = tmpnam(buf);
    (void)mktemp(buf);
    (void)OPEN("/tmp/project.db", O_RDWR | O_CREAT, 0600);
    return n;
}
