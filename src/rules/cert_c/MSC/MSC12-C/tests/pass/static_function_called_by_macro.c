/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: PASS - a macro's expansion calls the static, by a function-like macro or an object-like rename
 */
#include <stdio.h>

static void log_value(int v)
{
    (void)v;
}

static void flush_all(void)
{
    puts("done");
}

#define LOG(v) log_value(v)
#define FLUSH flush_all

void api(int v)
{
    LOG(v);
    FLUSH();
}
