/*
 * Rule: FIO42-C
 *
 * Status: PASS - Should NOT trigger FIO42-C violation
 *
 * Each close goes through a macro the file defines: one whose name is also
 * a common wrapper spelling, an object-like alias of close(), and a macro
 * that expands to that alias. Each expansion closes the handle it is given.
 */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#define CLOSE(f) fclose(f)
#define XCLOSE close
#define CLOSE_FD(fd) XCLOSE(fd)
#define CLOSE_STREAM(f) do { if ((f) != NULL) { fclose(f); } } while (0)

void closed_by_a_wrapper_named_macro(const char *path)
{
    FILE *f = fopen(path, "r");
    CLOSE(f);
}

void closed_by_an_alias(const char *path)
{
    int fd = open(path, O_RDONLY);
    XCLOSE(fd);
}

void closed_by_a_macro_over_an_alias(const char *path)
{
    int fd = open(path, O_RDONLY);
    CLOSE_FD(fd);
}

void closed_by_a_guarded_macro(const char *path)
{
    FILE *f = fopen(path, "r");
    CLOSE_STREAM(f);
}
