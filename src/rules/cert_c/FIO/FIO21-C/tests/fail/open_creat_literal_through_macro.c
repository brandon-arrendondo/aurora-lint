/*
 * Rule: FIO21-C
 * Source: regression
 * Status: FAIL - Should trigger FIO21-C violation
 *
 * open() with O_CREAT on a literal path under /var/tmp, inside a project
 * function-like macro: the literal is the invocation's argument, so it is
 * read where the macro is invoked.
 */

#include <fcntl.h>

#define CREATE_FILE(path) open((path), O_WRONLY | O_CREAT | O_TRUNC, 0600)

int open_log(void) {
    return CREATE_FILE("/var/tmp/app.log");
}
