/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: PASS - a keep-alive attribute spelled through a macro keeps the static
 */
#include <stdio.h>
#include "compiler.h" /* defines ATTRIBUTE_USED; not part of the scan */

#define MY_CONSTRUCTOR __attribute__((constructor))
#define INIT_ATTRS MY_CONSTRUCTOR

MY_CONSTRUCTOR static void init_tables(void)
{
    puts("init");
}

INIT_ATTRS static void init_more(void)
{
    puts("more");
}

ATTRIBUTE_USED static void kept_for_debugger(void)
{
    puts("kept");
}

void api(void)
{
    puts("api");
}

static void late_init(void) MY_CONSTRUCTOR;

static void late_init(void)
{
    puts("late");
}
