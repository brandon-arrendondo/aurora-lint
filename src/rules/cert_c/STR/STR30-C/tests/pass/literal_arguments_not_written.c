/*
 * Rule: STR30-C
 * Source: synthetic
 * Status: PASS - Literals reach only parameters nothing writes through
 *
 * A function named for changing something (setenv, setlocale, a project's
 * update_name) does not write into its const char * argument; a scanf
 * format is read, not written; a printf-style wrapper only reads its
 * format.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>

struct opt {
    const char *name;
};

static void update_name(struct opt *o, const char *n)
{
    o->name = n;
}

static void log_msg(char *buf, size_t n, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, n, fmt, ap);
    va_end(ap);
}

void func(struct opt *o, char *buf)
{
    int v;
    setenv("HOME", "/tmp", 1);
    setlocale(LC_ALL, "C");
    update_name(o, "x");
    if (scanf("%d", &v) == 1)
        log_msg(buf, 10, "%d", v);
}
